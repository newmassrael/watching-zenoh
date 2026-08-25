#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y616 (§7.13) — a wire flag composed into a header must be NAMED.

THE DEFECT THIS EXISTS FOR. R311y615 added `wire_const::FLAG_N_N` because every
construction site in the capture crate was spelling the network envelope's `N`
bit as the literal `0x20`, while the declaration side had had `FLAG_D_N` all
along. Naming it fixed nothing on its own: the constant shipped with ONE
consumer and the four fixtures beside it kept writing the number, so the crate
carried a constant and a literal for one bit and nothing would have reddened if
a fifth site had joined them. A constant with no gate is a naming exercise.

A literal flag is not a style problem. `header: Push::default().header | 0x20`
reads as a byte string wearing a struct: the reader cannot tell whether `0x20`
is the N bit, the Z bit or a typo, and the three times this crate lost a flag
that `Default` was baking, the literal is what hid it.

WHY A STATIC SCAN. The value is right either way — `FLAG_N_N` IS `0x20` — so no
test can distinguish them and no build can fail. The invariant is about the
SOURCE, so it is checked where it is true.

SCOPE, STATED RATHER THAN IMPLIED. This gate covers `crates/wz-capture` — the
capture / analyzer crate, the tree R311y615 named the constant for. It is NOT a
workspace-wide claim, and the count of sites elsewhere is PRINTED on every run
so the scope can never be mistaken for the whole. Those are §3.3's territory
(the literal-vs-named ext-header sweep), which is its own round: the workspace
has dozens of them, several in codegen-adjacent code where the named constant
does not exist yet, and a gate that reds on day one is a gate someone disables.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# A hex literal being OR-ed into a header byte, in either order:
#
#   header: Foo::default().header | 0x20      <- the shape R311y615 left behind
#   header: 0x1D | 0x20                       <- MID and flag both literal
#
# Deliberately NARROW. It does not flag a bare `0x20` anywhere else in a file:
# `0x20` is also 32, a buffer size, and the first printable ASCII character, and
# a scan that hunted the number rather than the POSITION would drown in them.
# What makes a site a defect is that a header is being composed out of an
# unnamed constant.
COMPOSITION = re.compile(
    r"""(?x)
    (?:
        \.header \s* \| \s* 0x[0-9A-Fa-f]+     # <expr>.header | 0xNN
      |
        header: \s* 0x[0-9A-Fa-f]+ \s* \|      # header: 0xNN | <expr>
    )
    """
)

REPO_ROOT = Path(__file__).resolve().parents[2]

# The tree this gate speaks for.
SCOPE = Path("crates/wz-capture")

# The rest of the workspace, counted and reported but not gated (§3.3).
SURVEY = (Path("crates"), Path("runtime"))

SKIP_PARTS = ("target", "vendor", ".git")

# Below this the scan resolved the wrong root: wz-capture is a ten-file crate
# plus its tests, so a run that reads fewer than this found nothing to look at
# and must not report OK -- the failure mode `duplicate_module_lint` hit on its
# first run (0 files, exit 0).
MIN_FILES = 8


def strip_comment(line: str) -> str:
    """Everything before a `//`, so PROSE about a literal is not a literal.

    Crude on purpose: a `//` inside a string literal would truncate the line
    early, which can only ever LOSE a candidate on that line, and every
    construction site this looks for is a struct field rather than a string.
    Doc comments describing the very defect this gate exists for are the common
    case and must not be flagged -- `lib.rs` carries one.
    """
    return line.split("//", 1)[0]


def offenders(root: Path, tree: Path) -> tuple[list[str], int]:
    """`(findings, files_scanned)` under `root / tree`."""
    found: list[str] = []
    scanned = 0
    base = root / tree
    if not base.is_dir():
        return found, 0
    for path in sorted(base.rglob("*.rs")):
        rel = path.relative_to(root)
        if any(part in SKIP_PARTS for part in rel.parts):
            continue
        scanned += 1
        for n, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            code = strip_comment(line)
            if COMPOSITION.search(code):
                found.append(f"{rel}:{n}: {line.strip()}")
    return found, scanned


def main() -> int:
    findings, scanned = offenders(REPO_ROOT, SCOPE)

    if scanned < MIN_FILES:
        print(
            f"literal-wire-flag lint: FAIL — scanned {scanned} file(s) under "
            f"{REPO_ROOT / SCOPE}, fewer than the {MIN_FILES} that tree has. A "
            f"checker that found nothing to read must not report OK.",
            file=sys.stderr,
        )
        return 1

    # The survey half: counted every run so this gate's scope is a printed
    # number rather than an assumption a reader has to make.
    outside = 0
    for tree in SURVEY:
        other, _ = offenders(REPO_ROOT, tree)
        outside += sum(1 for f in other if not f.startswith(str(SCOPE)))

    if findings:
        print("literal-wire-flag lint: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nA flag OR-ed into a header must be a named `wire_const`, not a hex\n"
            "literal: the value is identical, so no test can tell them apart, and\n"
            "the literal is what hid a lost flag three times in this crate.\n"
            "Use the constant (e.g. `wz_codecs::wire_const::FLAG_N_N` for the\n"
            "network `N` bit); add one beside its siblings if it does not exist.",
            file=sys.stderr,
        )
        return 1

    print(
        f"literal-wire-flag lint: OK ({scanned} file(s) under {SCOPE}, "
        f"0 literal flag composition(s); {outside} outside this gate's scope "
        f"— §3.3, not covered here)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
