#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

R311y795 CLOSED THE THREE GAPS y794 WROTE DOWN, and measuring them first was
the point -- y794's own lesson was that a gap nobody measured turned out to be
the larger half. This time the three measured very differently:

  * `#[cfg]`-gated `use` -- THE CLAIM WAS FALSE. 130 such sites over 6 crates,
    and every one was already captured: the attribute sits on the line ABOVE and
    the `use` line itself is what this reader matches. Removed rather than
    "fixed", because a gap that does not exist is not closed by code.
  * RE-EXPORT chains -- REAL. `[Foo]` in a crate that wrote `use wz_a::Foo`,
    where wz_a itself wrote `pub use wz_x::Foo`, is an edge to wz_x and was read
    as one to wz_a. 8 crates re-export 158 wz identifiers between them; the
    edges actually missed are 3, all into wz-session-core (wz-capi-c,
    wz-capi-core, wz-runtime-tokio-test-support). Resolved transitively below.
  * GLOB imports -- REAL and tiny. `use wz_x::*` binds names this reader cannot
    enumerate. 6 sites, 1 crate pair, 1 missed edge (wz-session-core ->
    wz-session-core-test-support).

R311y796 MEASURED THE LAST TWO AND ALL THREE PARTS CAME BACK EMPTY:

  * MODULE-PATH re-export (`pub use crate::inner::Thing`) -- 37 such identifiers
    over 2 crates and NONE traces to a wz crate. The concern was also
    structurally wrong: the map below is keyed by CRATE, not by file, so a
    `pub use wz_x::Thing` anywhere in the crate already registers it and the
    module path inside that crate never mattered.
  * `#[doc = "..."]` attributes -- 19 sites, 0 containing a link at all.
  * MACRO-generated docs -- 14 `macro_rules!` DO emit doc comments carrying
    links, and 0 of those links name a foreign wz crate.

The third is live machinery that merely happens to point inward today, so its
emptiness is PINNED by `--check-blind-spots` (run-ci Layer C0d) rather than
asserted in prose. The check lives here because this reader is the authority on
what it cannot see; a gate elsewhere would drift from it.

USAGE
    doclink_dependents.py <crate-name>...
    doclink_dependents.py --check-blind-spots

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
# R311y795 — the RE-EXPORT half: `pub use wz_x::Foo;` makes Foo reachable as the
# re-exporting crate's own, so a downstream `use that_crate::Foo` + `[Foo]` is
# really an edge to wz_x.
PUB_USE = re.compile(r"^\s*pub\s+use\s+(wz_[a-z0-9_]+)::([^;]+);")
# R311y795 — `use wz_x::*;` (or `use wz_x::a::*;`) binds names this reader cannot
# enumerate, so the import itself is taken as the edge.
GLOB_USE = re.compile(r"^\s*(?:pub\s+)?use\s+(wz_[a-z0-9_]+)::(?:[^;]*::)?\*\s*;")
# The qualified link spelling, both backtick forms.
QUAL = re.compile(r"\[`?(wz_[a-z0-9_]+)::")
IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")


def repo_root() -> pathlib.Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
    )
    return pathlib.Path(out.stdout.strip())


def read_files(crates_dir: pathlib.Path):
    """(source crate, lines) for every crate source file, target dirs excluded."""
    for path in crates_dir.rglob("*.rs"):
        parts = path.relative_to(crates_dir).parts
        if not parts or "target" in parts:
            continue
        try:
            yield parts[0], path.read_text(errors="ignore").splitlines()
        except OSError:
            continue


def reexports(crates_dir: pathlib.Path) -> dict:
    """crate (module form) -> {ident: the wz crate it was re-exported FROM}."""
    out: dict = {}
    for source, lines in read_files(crates_dir):
        module = source.replace("-", "_")
        for line in lines:
            m = PUB_USE.match(line)
            if m:
                for ident in IDENT.findall(m.group(2)):
                    out.setdefault(module, {})[ident] = m.group(1)
    return out


def origin(module: str, ident: str, chain: dict) -> str:
    """Walk `module::ident` back to the crate that first exported it.

    Bounded by a visited set rather than a hop count: the re-export map is tiny
    and a cycle is the only thing that could not terminate. One hop is what the
    measurement found (3 missed edges, all into wz-session-core), but hop count
    is not a property worth hard-coding -- a second re-export would be silently
    missed by a fixed `1`.
    """
    seen = {module}
    while True:
        nxt = chain.get(module, {}).get(ident)
        if nxt is None or nxt in seen:
            return module
        seen.add(nxt)
        module = nxt


def edges(crates_dir: pathlib.Path) -> dict:
    """target crate name -> set of crate names whose docs link into it."""
    graph: dict = {}
    chain = reexports(crates_dir)

    def add(target_module: str, source: str) -> None:
        graph.setdefault(target_module.replace("_", "-"), set()).add(source)

    for source, lines in read_files(crates_dir):
        imported = {}
        globs = set()
        for line in lines:
            m = USE.match(line)
            if m:
                for ident in IDENT.findall(m.group(2)):
                    imported[ident] = m.group(1)
            g = GLOB_USE.match(line)
            if g:
                globs.add(g.group(1))

        # A glob import is taken as an edge on its own: the names it binds
        # cannot be enumerated here, so the file's docs may name any of them.
        # An over-approximation whose whole cost today is one crate pair.
        for target in globs:
            add(target, source)

        for line in lines:
            for target in QUAL.findall(line):
                add(target, source)
            m = LINK.match(line)
            if m and m.group(1) in imported:
                direct = imported[m.group(1)]
                add(direct, source)
                # And the crate the item actually came from, if `direct` is
                # only passing it through.
                add(origin(direct, m.group(1), chain), source)
    return graph


# R311y796 — a doc comment EMITTED BY A MACRO is invisible to `edges()`: the
# link sits inside a macro body, and the crate it lands in is the expansion site
# rather than the file this reader is looking at. Measured empty (14 macros emit
# linked docs, 0 of the links name a foreign wz crate), and empty is what this
# pins -- the machinery is live, so the emptiness is a fact about today rather
# than a property of the language.
MACRO_BODY = re.compile(r"macro_rules!\s+(\w+)\s*\{(.*?)\n\}", re.S)
ANY_LINK = re.compile(r"\[`?([A-Za-z_][A-Za-z0-9_:]*)`?\]")
DOC_ATTR = re.compile(r'#\[doc\s*=\s*"([^"]*)"')


def check_blind_spots(crates_dir: pathlib.Path) -> int:
    """0 when this reader's known blind spots hold nothing; 1 when they do."""
    findings = []
    for source, lines in read_files(crates_dir):
        text = "\n".join(lines)
        imported = {}
        for line in lines:
            m = USE.match(line)
            if m:
                for ident in IDENT.findall(m.group(2)):
                    imported[ident] = m.group(1)

        def foreign(target: str):
            head = target.split("::")[0]
            if head.startswith("wz_"):
                return head
            return imported.get(head)

        # A `#[doc = "..."]` body carrying a link.
        for line in lines:
            for body in DOC_ATTR.findall(line):
                for target in ANY_LINK.findall(body):
                    owner = foreign(target)
                    if owner:
                        findings.append(f"{source}: #[doc] attribute links [{target}] -> {owner}")

        # A macro body emitting a doc comment that carries a link.
        if "macro_rules!" in text:
            for m in MACRO_BODY.finditer(text):
                for line in m.group(2).splitlines():
                    if "#[doc" not in line and "///" not in line:
                        continue
                    for target in ANY_LINK.findall(line):
                        owner = foreign(target)
                        if owner:
                            findings.append(
                                f"{source}: macro {m.group(1)}! emits [{target}] -> {owner}"
                            )

    if findings:
        print(
            "doclink_dependents: BLIND SPOT NOW OCCUPIED -- "
            f"{len(findings)} doc link(s) this reader cannot attribute:",
            file=sys.stderr,
        )
        for f in sorted(set(findings)):
            print(f"  - {f}", file=sys.stderr)
        print(
            "  A link emitted by a macro, or written in a #[doc] attribute, lands in the\n"
            "  EXPANSION site rather than in the file read here, so the crate edge it\n"
            "  creates is missed and pre-push gate 4 measures one crate too few. This was\n"
            "  measured empty at R311y796; it is not any more. Teach edges() to read the\n"
            "  spelling above, or record why that edge does not need the gate.",
            file=sys.stderr,
        )
        return 1

    print("doclink_dependents: blind spots empty (no macro- or attribute-emitted doc link "
          "names a foreign wz crate)")
    return 0


def main(argv) -> int:
    if not argv:
        print(
            "doclink_dependents: usage: doclink_dependents.py <crate-name>... |"
            " --check-blind-spots",
            file=sys.stderr,
        )
        return 2

    if argv[0] == "--check-blind-spots":
        if len(argv) != 1:
            print("doclink_dependents: --check-blind-spots takes no other argument", file=sys.stderr)
            return 2
        return check_blind_spots(repo_root() / "crates")

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
