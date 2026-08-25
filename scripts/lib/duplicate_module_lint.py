#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y608 (no register item) — one module name may be declared once per file scope.

THE DEFECT THIS EXISTS FOR. R311y607 added `pub mod scouting;` to
`wz-session-core/src/lib.rs`, which already declared `pub mod scouting { ... }`
1000 lines below — the SCE-generated active-scouting state machine. The two sit
behind DISJOINT features (`codec-scout`/`codec-hello` versus `scouting-active`),
so rustc raises E0428 only for a build that turns on BOTH, and every build that
round ran turned on one. Three hosted jobs then failed on it at once (Layer C1's
workspace feature unification, Layer M's multicast lane, Layer C1bf's
`--all-features` clippy) for one cause.

WHY A STATIC SCAN AND NOT A BUILD. Catching this by BUILDING needs the one
feature combination that unions the two cfgs, and the set of combinations grows
with every feature — a lane that happens to cover it today is not a gate, it is
a coincidence, which is exactly how this shipped. The name-collision invariant
does not depend on features at all: two declarations of one name in one scope
are a defect under EVERY combination, including the ones nobody built. So it is
checked where it is true, by reading the declarations.

WHAT IT DELIBERATELY DOES NOT ALLOW. A `#[cfg(X)] mod m;` / `#[cfg(not(X))] mod
m;` pair is legal Rust and a real pattern elsewhere — two implementations of one
module. This workspace has none (measured: zero duplicate names across every
crate root at R311y608), and admitting the shape would mean deciding whether two
arbitrary cfg predicates are disjoint, which is where a checker stops being a
checker. If such a pair is ever wanted here, that is a decision to make and to
record, not a hole to leave open in advance.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

# A module declaration at FILE SCOPE — column zero, so a `mod` nested inside an
# `impl`, a function, or a `mod x { ... }` block is not read as a sibling of the
# outer ones. Nested scopes are their own namespaces and rustc judges them
# under the same rule one level down.
DECL = re.compile(
    r"^(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*[;{]",
    re.MULTILINE,
)

# Trees this workspace does not author: vendored upstreams keep their own
# layout, and build output is regenerated rather than reviewed.
SKIP_PARTS = ("target", "vendor", ".git")


def declarations(text: str) -> list[tuple[str, int]]:
    """Every file-scope module name in `text`, with its 1-based line."""
    return [(m.group(1), text.count("\n", 0, m.start()) + 1) for m in DECL.finditer(text)]


REPO_ROOT = Path(__file__).resolve().parents[2]

# Below this the scan is not a weak result, it is a BROKEN one: this workspace
# has over a thousand Rust files, so a run that reads a handful has resolved the
# wrong root and its `OK` means "found nothing to look at". The first run of
# this script did exactly that (0 files, exit 0) after being moved one directory
# deeper, and reported OK.
MIN_FILES = 500


def main() -> int:
    root = REPO_ROOT
    failures: list[str] = []
    scanned = 0

    for path in sorted(root.rglob("*.rs")):
        rel = path.relative_to(root)
        if any(part in SKIP_PARTS for part in rel.parts):
            continue
        scanned += 1
        seen: dict[str, list[int]] = defaultdict(list)
        for name, line in declarations(path.read_text(encoding="utf-8", errors="replace")):
            seen[name].append(line)
        for name, lines in seen.items():
            if len(lines) > 1:
                where = ", ".join(f"{rel}:{n}" for n in lines)
                failures.append(
                    f"module `{name}` is declared {len(lines)} times at file scope: {where}"
                )

    if scanned < MIN_FILES:
        print(
            f"duplicate-module lint: FAIL — scanned {scanned} file(s) under {root}, "
            f"fewer than the {MIN_FILES} this workspace has. A checker that found "
            f"nothing to read must not report OK.",
            file=sys.stderr,
        )
        return 1

    if failures:
        print("duplicate-module lint: FAIL", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nTwo declarations of one name in one scope are a defect under every\n"
            "feature combination — rustc only says so for a build that enables both.\n"
            "Rename one of them.",
            file=sys.stderr,
        )
        return 1

    print(f"duplicate-module lint: OK ({scanned} file(s), 0 duplicate declaration(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
