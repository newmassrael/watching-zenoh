#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2173 (no register item) — every value family says what an UNRECOGNISED value means.

Closes item 550 of the unregistered register, which lives outside this tree and
so has no `debt-` id to cite -- the position `debt_plane_census.py` and
`capi_c_config_surface.py` record for themselves.

## The gap, which is TWO facts and only one of them had been counted

`wz_dissect.h` publishes families of `#define`d values a consumer switches on.
For KIND the header is careful: `UNDECODABLE` is THIS READER FAILING and
`UNKNOWN` is A MID THIS BUILD DOES NOT RECOGNISE, and it says in words that
"Both are answers, and neither is the absence of one".

  1. THE OTHER FAMILIES HAVE NOTHING OF THE KIND. Measured before this gate:
     ORIGIN, ANCHOR and FLAG carry no member and no sentence about a value the
     reader does not recognise.
  2. AND NEITHER DOES KIND, for the THIRD kind of not-knowing. `UNDECODABLE` is
     the reader failing and `UNKNOWN` is the wire being strange; the third is
     the CONSUMER'S OWN BUILD being older than the library it linked. The
     header goes as far as "a consumer's switch falls through to its own
     default" and stops -- it never says what that default MEANS. A consumer
     folding it into `UNKNOWN` would report "the wire sent something strange"
     about a perfectly ordinary message, which is the confident wrong answer
     this workspace refuses harder than silence.

## Why a FORM and not prose

Prose is what open-debt item 530 is about: a sentence nobody measures rots
silently. So each family carries a marker in its own comment block,

    @unknown <FAMILY> <policy>

and -- where the family ALSO reports not-knowing as a value --

    @unknown-sentinel <FAMILY> <MEMBER>

The two markers are what make the three kinds of not-knowing MACHINE-DISTINCT:
the sentinel names the wire's, the policy names the consumer's, and a reader
failing is a value in its own right (KIND's `UNDECODABLE`).

## The policies are a CLOSED vocabulary, and each one has a CONSEQUENCE

A classification that only renamed the problem would be the escape hatch this
repository keeps finding in its own exception lists. So every policy implies
something a machine can check, and the gate checks it:

  * `newer-build`      -- an enumeration; an unrecognised value means the
                          library is NEWER THAN THIS HEADER. Consequence: the
                          values are CONTIGUOUS (the header's own argument at
                          KIND -- "the numbers in between are contiguous so a
                          kind added later gets the next one and a consumer's
                          switch falls through to its own default rather than
                          onto a neighbour's case"), ignoring a sentinel this
                          family declares.
  * `ignore-bits`      -- a bitfield; an unrecognised BIT is ignored rather
                          than being a value at all. Consequence: every member
                          is a power of two.
  * `caller-supplied`  -- the caller PASSES this, so the library rejects what
                          it does not know. Consequence: the family's own
                          comment names the refusal code.
  * `not-an-enumeration` -- not a switchable family. Consequence: at most one
                          member.

## The population is DERIVED, and derived from the COMPILER

Not from a regex over the header, and the reason is measured: the probe that
filed item 550 used one, and it silently missed `WZ_DISSECT_OK` and
`WZ_DISSECT_H` -- two of the thirty definitions -- because its pattern needed
two underscore-separated parts. Worse, its own exclusion list named `OK` and
`H`, so it was excusing families it had never been able to see. An exclusion
for something that cannot occur is proof the list was never checked.

So the values come from `cc -dM -E`: whatever the preprocessor says the header
defines, filtered to this ABI's prefix. A family the header gains is in the
population on the same commit, and a family with no marker is a FAILURE rather
than a silence.

A population of zero is a FAIL and never a quiet pass, for this workspace's
standing reason.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = pathlib.Path(
    os.environ.get(
        "WZ_CAPI_DISSECT_HEADER",
        ROOT / "crates" / "wz-capi-dissect" / "include" / "wz_dissect.h",
    )
)

PREFIX = "WZ_DISSECT_"
MARKER = re.compile(r"@unknown\s+([A-Z0-9]+)\s+([a-z-]+)")
SENTINEL = re.compile(r"@unknown-sentinel\s+([A-Z0-9]+)\s+([A-Z0-9_]+)")
DEFINE_LINE = re.compile(r"^#define\s+(WZ_DISSECT_[A-Z0-9_]*)", re.M)

POLICIES = (
    "newer-build",
    "ignore-bits",
    "caller-supplied",
    "not-an-enumeration",
)


def defined_macros(header: pathlib.Path) -> dict[str, str]:
    """`{macro: value}` for this ABI's macros, AS THE PREPROCESSOR SEES THEM."""
    cc = os.environ.get("CC", "cc")
    if shutil.which(cc) is None:
        return {}
    with tempfile.TemporaryDirectory() as tmp:
        tu = pathlib.Path(tmp) / "tu.c"
        tu.write_text(f'#include "{header.name}"\n', encoding="utf-8")
        proc = subprocess.run(
            [cc, "-dM", "-E", "-I", str(header.parent), str(tu)],
            capture_output=True,
            text=True,
            check=False,
        )
    if proc.returncode != 0:
        return {}
    out: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 2 and parts[0] == "#define" and parts[1].startswith(PREFIX):
            out[parts[1]] = parts[2] if len(parts) > 2 else ""
    return out


def family_of(macro: str) -> str:
    """The FAMILY a macro belongs to: the first token after the prefix.

    `WZ_DISSECT_KIND_INIT` -> `KIND`; `WZ_DISSECT_OK` -> `OK`;
    `WZ_DISSECT_H` -> `H`. Every macro lands in exactly one family, which is
    what stops the two the filing probe could not see from vanishing again.
    """
    return macro[len(PREFIX) :].split("_", 1)[0]


def as_int(raw: str) -> int | None:
    """The integer a macro's replacement list denotes, or None."""
    text = raw.strip().rstrip("uU").strip("()").strip().rstrip("uU")
    try:
        return int(text, 0)
    except ValueError:
        return None


def spans(text: str) -> list[tuple[str, int, int]]:
    """`[(family, start, end)]` — each family's own comment block.

    The span runs from the end of the PREVIOUS `#define` to this family's
    FIRST one, which is the block a reader of that family is already looking
    at. A marker outside every span pins nothing, and is refused for the
    reason `capi_header_subsumption.py` refuses a floating subsumption note.
    """
    out: list[tuple[str, int, int]] = []
    seen: set[str] = set()
    previous_end = 0
    for m in DEFINE_LINE.finditer(text):
        fam = family_of(m.group(1))
        if fam not in seen:
            seen.add(fam)
            out.append((fam, previous_end, m.start()))
        previous_end = m.end()
    return out


# ── The damage probes ────────────────────────────────────────────────────
#
# R2137's lesson, applied rather than cited: a self-test whose fixture would
# have passed the OLD implementation too is green from birth and proves
# nothing. Each fixture below is built so that the ONE check it is aimed at is
# the only thing wrong with it -- every other family in it is fully classified
# -- and the expected NEEDLE is a phrase only that check emits.
#
# The list is also the gate's answer to "which failure paths are exercised":
# a total would read as coverage, so the run prints the breakdown.
DAMAGE_PROBES: tuple[tuple[str, str, str], ...] = (
    (
        "unclassified family",
        "#define WZ_DISSECT_ZZ_A 1\n",
        "has no `@unknown ZZ",
    ),
    (
        "unknown policy word",
        "/* @unknown ZZ sometimes-fine */\n#define WZ_DISSECT_ZZ_A 1\n",
        "names no known policy",
    ),
    (
        "newer-build with a hole",
        "/* @unknown ZZ newer-build */\n"
        "#define WZ_DISSECT_ZZ_A 1\n#define WZ_DISSECT_ZZ_C 3\n",
        "NOT contiguous",
    ),
    (
        "ignore-bits that is not a bit",
        "/* @unknown ZZ ignore-bits */\n"
        "#define WZ_DISSECT_ZZ_A 1\n#define WZ_DISSECT_ZZ_B 3\n",
        "is not a single power of two",
    ),
    (
        "caller-supplied naming no refusal",
        "/* @unknown ZZ caller-supplied */\n#define WZ_DISSECT_ZZ_A 1\n",
        "names no `WZ_DISSECT_ERR_",
    ),
    (
        "not-an-enumeration with two members",
        "/* @unknown ZZ not-an-enumeration */\n"
        "#define WZ_DISSECT_ZZ_A 1\n#define WZ_DISSECT_ZZ_B 2\n",
        "which is a family a consumer can switch on",
    ),
    (
        "sentinel naming a member that does not exist",
        "/* @unknown ZZ newer-build\n * @unknown-sentinel ZZ NOPE */\n"
        "#define WZ_DISSECT_ZZ_A 1\n",
        "which this header does not define",
    ),
    (
        "marker pinned to nothing",
        "#define WZ_DISSECT_ZZ_A 1\n/* @unknown ZZ newer-build */\n",
        "is outside every family's comment block",
    ),
)


def selftest() -> int:
    """Drive every FAIL path through a fixture, and report the breakdown."""
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        good = pathlib.Path(tmp) / "clean.h"
        good.write_text(
            "/* @unknown ZZ newer-build */\n#define WZ_DISSECT_ZZ_A 1\n",
            encoding="utf-8",
        )
        env = dict(os.environ)
        env["WZ_CAPI_DISSECT_HEADER"] = str(good)
        clean = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve())],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        # The control arm. Without it a gate that failed on EVERYTHING would
        # pass every probe below and still be useless.
        if clean.returncode != 0:
            failures.append(
                "the CLEAN fixture did not pass -- every damage probe below "
                f"would then be meaningless: {clean.stderr.strip()}"
            )

        for name, body, needle in DAMAGE_PROBES:
            fixture = pathlib.Path(tmp) / "damaged.h"
            fixture.write_text(body, encoding="utf-8")
            env["WZ_CAPI_DISSECT_HEADER"] = str(fixture)
            proc = subprocess.run(
                [sys.executable, str(pathlib.Path(__file__).resolve())],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            if proc.returncode == 0:
                failures.append(f"{name}: the gate PASSED a fixture it must refuse")
            elif needle not in proc.stderr:
                failures.append(
                    f"{name}: refused, but not for the stated reason -- "
                    f"{needle!r} is absent from: {proc.stderr.strip()}"
                )

    if failures:
        print(
            f"capi-unknown-policy selftest: FAIL -- {len(failures)} of "
            f"{len(DAMAGE_PROBES)} probe(s):",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"  capi-unknown-policy selftest: {len(DAMAGE_PROBES)} damage probe(s) "
        f"refused for their own stated reason, and the clean fixture passes -- "
        + "; ".join(name for name, _, _ in DAMAGE_PROBES)
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="drive every FAIL path through a fixture and report the breakdown",
    )
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    if not HEADER.is_file():
        print(
            f"capi-unknown-policy: FAIL -- {HEADER} is missing, so this gate "
            f"has measured nothing.",
            file=sys.stderr,
        )
        return 1

    text = HEADER.read_text(encoding="utf-8")
    macros = defined_macros(HEADER)
    if not macros:
        print(
            "capi-unknown-policy: FAIL -- the preprocessor reported NO "
            f"{PREFIX}* macro. Either no C compiler is installed or the header "
            "does not preprocess; a gate that cannot reach its population must "
            "not report green.",
            file=sys.stderr,
        )
        return 1

    families: dict[str, list[tuple[str, str]]] = {}
    for macro, value in sorted(macros.items()):
        families.setdefault(family_of(macro), []).append((macro, value))

    declared: dict[str, str] = {}
    claimed: set[tuple[int, int]] = set()
    family_spans = {fam: (a, b) for fam, a, b in spans(text)}
    problems: list[str] = []

    for fam, (start, end) in family_spans.items():
        block = text[start:end]
        for m in MARKER.finditer(block):
            claimed.add((start + m.start(), start + m.end()))
            if m.group(1) != fam:
                problems.append(
                    f"`@unknown {m.group(1)} ...` sits in {fam}'s comment "
                    f"block. A marker naming another family pins nothing "
                    f"where a reader of THAT family will look."
                )
                continue
            declared[fam] = m.group(2)

    sentinels: dict[str, str] = {}
    for fam, (start, end) in family_spans.items():
        for m in SENTINEL.finditer(text[start:end]):
            claimed.add((start + m.start(), start + m.end()))
            if m.group(1) != fam:
                problems.append(
                    f"`@unknown-sentinel {m.group(1)} ...` sits in {fam}'s block."
                )
                continue
            sentinels[fam] = f"{PREFIX}{fam}_{m.group(2)}"

    # A marker outside every family's block states something and pins nothing.
    for pattern in (MARKER, SENTINEL):
        for m in pattern.finditer(text):
            if (m.start(), m.end()) not in claimed:
                line = text.count("\n", 0, m.start()) + 1
                problems.append(
                    f"{HEADER.name}:{line}: `{m.group(0)}` is outside every "
                    f"family's comment block, so nothing holds it to a family."
                )

    for fam in sorted(families):
        members = families[fam]
        policy = declared.get(fam)
        if policy is None:
            problems.append(
                f"{fam} ({len(members)} member(s)) has no `@unknown {fam} "
                f"<{'|'.join(POLICIES)}>` in its comment block. What a "
                f"consumer's `default` MEANS for this family is undecided, "
                f"which is open-debt item 550 exactly."
            )
            continue
        if policy not in POLICIES:
            problems.append(
                f"{fam}: `@unknown {fam} {policy}` names no known policy. "
                f"One of {', '.join(POLICIES)}."
            )
            continue

        sentinel = sentinels.get(fam)
        if sentinel is not None and sentinel not in macros:
            problems.append(
                f"{fam}: `@unknown-sentinel` names {sentinel}, which this "
                f"header does not define."
            )
            sentinel = None

        values = [(name, as_int(v)) for name, v in members]
        if policy == "newer-build":
            nums = sorted(
                n for name, n in values if n is not None and name != sentinel
            )
            if not nums:
                problems.append(
                    f"{fam}: declared `newer-build` and no member has a "
                    f"readable integer value, so contiguity cannot be checked."
                )
            elif nums != list(range(nums[0], nums[0] + len(nums))):
                problems.append(
                    f"{fam}: declared `newer-build` but its values {nums} are "
                    f"NOT contiguous. The header's own argument for contiguity "
                    f"is that a value added later takes the next number and a "
                    f"consumer's switch falls to its default rather than onto "
                    f"a neighbour's case; a hole breaks that."
                )
        elif policy == "ignore-bits":
            bad = [
                name
                for name, n in values
                if n is None or n <= 0 or (n & (n - 1)) != 0
            ]
            if bad:
                problems.append(
                    f"{fam}: declared `ignore-bits` but {', '.join(bad)} "
                    f"is not a single power of two, so 'an unrecognised BIT is "
                    f"ignored' is not what this family does."
                )
        elif policy == "caller-supplied":
            block = text[slice(*family_spans[fam])]
            if "ERR_" not in block:
                problems.append(
                    f"{fam}: declared `caller-supplied` -- the library refuses "
                    f"what it does not know -- but its comment block names no "
                    f"`WZ_DISSECT_ERR_*` code, so a caller is not told HOW it "
                    f"is refused."
                )
        elif policy == "not-an-enumeration" and len(members) > 1:
            problems.append(
                f"{fam}: declared `not-an-enumeration` but has {len(members)} "
                f"members ({', '.join(n for n, _ in members)}), which is a "
                f"family a consumer can switch on."
            )

    if problems:
        print(
            f"capi-unknown-policy: FAIL -- {len(problems)} problem(s) over "
            f"{len(families)} family(ies) / {len(macros)} macro(s):",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    by_policy: dict[str, list[str]] = {}
    for fam, policy in declared.items():
        by_policy.setdefault(policy, []).append(fam)
    # The BREAKDOWN and not just a total: a skip reads like coverage, and this
    # workspace has paid for that twice (R2167).
    detail = "; ".join(
        f"{p}: {', '.join(sorted(by_policy[p]))}" for p in POLICIES if p in by_policy
    )
    named = ", ".join(f"{f}={sentinels[f]}" for f in sorted(sentinels)) or "none"
    print(
        f"  capi-unknown-policy: {len(macros)} macro(s) in {len(families)} "
        f"family(ies), every one classified -- {detail}. Families that ALSO "
        f"report not-knowing as a value: {named}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
