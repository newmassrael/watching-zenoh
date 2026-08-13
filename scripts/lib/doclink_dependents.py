#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y794 (no register item) — expand a crate set to every workspace crate
whose DOCS LINK INTO one of them. Prints the union, one crate per line, sorted.

WHY IT EXISTS. R311y792 gave the pre-push hook a doc-link gate over the crates a
push CHANGES; R311y793 widened it to the crates that link INTO them, matching the
QUALIFIED spelling `[wz_session_core::Foo]`. That round wrote down what it could
not see, and this round measured it: the spelling it missed is the LARGER half.

    qualified   `[wz_session_core::Foo]`     ~250 sites
    unqualified `[Foo]` + `use wz_session_core::Foo`   304 sites, 35 crate pairs

The two disagree on the crate SET, which is the thing the caller acts on:
wz-session-core is linked from 14 crates by the qualified spelling and 9 by the
unqualified one, and the union is 18 -- four crates (wz-access-control,
wz-mcu-multicast-e2e, wz-mcu-session-acceptor, wz-statechart-bridge) are reachable
ONLY through the unqualified form. A gate that saw one spelling would have
measured 14 of 18 and reported clean over the other four.

WHY NOT THE DEPENDENCY GRAPH, unchanged from y793: reverse cargo dependencies of
wz-session-core are very nearly the whole workspace and almost none of those edges
carry a doc link. The link TEXT is the population that can actually break.

HOW THE UNQUALIFIED FORM IS RESOLVED. rustdoc resolves a bare `[Foo]` through the
file's imports, so this reads the same thing: for each file, the `use wz_x::..`
lines give an identifier -> crate map, and a doc-comment link naming one of those
identifiers is an edge to that crate. It is a per-FILE map because that is the
scope rustdoc itself resolves in.

WHAT IT STILL CANNOT SEE, stated rather than left to be rediscovered: a link
through a glob import (`use wz_x::*`), through a local re-export chain, or to an
identifier whose `use` is behind a `#[cfg]` this reader does not evaluate.

USAGE
    doclink_dependents.py <crate-name>...

A name that is not a workspace member passes through unchanged: the caller owns
its own crate-set discipline, and the lane that consumes this refuses an unknown
name for real. An EMPTY argument list is refused (exit 2) -- a caller that
computed no crates must not be handed a clean answer.
"""

import pathlib
import re
import subprocess
import sys

# `[`Foo`]` and `[Foo]` in a doc comment. Anchored at the doc-comment marker so
# ordinary code and plain `//` comments do not contribute edges.
LINK = re.compile(r"^\s*(?://[/!])\s*.*?\[`?([A-Za-z_][A-Za-z0-9_]*)`?\]")
# `use wz_x::a::{B, C};` / `pub use wz_x::D;`
USE = re.compile(r"^\s*(?:pub\s+)?use\s+(wz_[a-z0-9_]+)::([^;]+);")
# The qualified link spelling, both backtick forms.
QUAL = re.compile(r"\[`?(wz_[a-z0-9_]+)::")
IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")


def repo_root() -> pathlib.Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
    )
    return pathlib.Path(out.stdout.strip())


def edges(crates_dir: pathlib.Path) -> dict:
    """target crate name -> set of crate names whose docs link into it."""
    graph: dict = {}
    for path in crates_dir.rglob("*.rs"):
        parts = path.relative_to(crates_dir).parts
        if not parts or "target" in parts:
            continue
        source = parts[0]
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue

        imported = {}
        for line in lines:
            m = USE.match(line)
            if m:
                for ident in IDENT.findall(m.group(2)):
                    imported[ident] = m.group(1)

        for line in lines:
            for target in QUAL.findall(line):
                graph.setdefault(target.replace("_", "-"), set()).add(source)
            m = LINK.match(line)
            if m and m.group(1) in imported:
                target = imported[m.group(1)].replace("_", "-")
                graph.setdefault(target, set()).add(source)
    return graph


def main(argv) -> int:
    if not argv:
        print("doclink_dependents: usage: doclink_dependents.py <crate-name>...", file=sys.stderr)
        return 2

    root = repo_root()
    graph = edges(root / "crates")

    out = set(argv)
    for crate in argv:
        out |= graph.get(crate, set())

    for name in sorted(out):
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
