#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2250 (no register item) -- a name this tree's TOOLING prose spells as code
must be a name this tree carries.

Closes item 600 of the unregistered register, which lives outside this
repository -- which is why the citation above reads "no register item", the
same way `armed_oracle_census.py` does for 562 and `cdylib_soname_gate.py` for
521. The item is named in full below, which is what a reader grepping for it
will find.

## The defect this ends

`armed_oracle_census.py` opened with a paragraph saying its narrow arming
pattern left a hole and that the hole was CLOSED rather than stated: every
other `WZ_..._REQUIRE=1` in `run-ci.sh` had to be followed by an English
connective drawn from a named word list. A reader finished that paragraph
believing a list decided it. No such name existed anywhere in the tree. The
implementation had never had one: `unclassifiable()` decides POSITIONALLY --
the line is a `#` comment, or the occurrence sits inside something being
echoed -- and the comment on that function records why the word list was
thrown away, which is that a word list is an exemption table and adding to it
is indistinguishable from excusing a real arming.

The implementation's judgement was the right one. What was wrong was the
prose, so the repair was the prose. What had no instrument at all was the
CLASS: a discarded design that survives as a NAME. The next reader either
goes looking for a thing that is not there, or -- worse, and this is the shape
`WZ_C1BC_REQUIRE` took before R2247 -- takes the sentence as evidence that a
hole is closed.

## The population is DERIVED, in both directions

Two derivations meet here, and neither is a list somebody kept.

  * WHERE PROSE IS. Per language, structurally: a Python file's prose is its
    `#` comments plus the docstrings `ast` reports, which is not the same as
    "every string literal" -- `os.environ.get("WZ_UPSTREAM_FEATURE_METADATA")`
    is CODE and is how an environment name is spelled. A hash-comment file's
    prose is its `#` lines. Markdown, plain text, and the atomic store's JSON
    are prose ENTIRELY.
  * WHAT A CODE SPAN IS. A backticked span whose whole content is ONE
    identifier -- an UPPER_SNAKE constant or a `name()` call, optionally
    `$`-sigilled, optionally carrying the `=value` an environment arming is
    written with. Backticks are this tree's way of saying "this is an
    identifier", and that claim is the subject here; the same word in running
    text claims nothing and is not read. A span holding a command or an
    expression is a QUOTATION rather than a name, and prose may quote something
    that was removed. Spans WRAP, so they are read from a run of consecutive
    prose lines joined back together: reading line by line lost 25 names.

A name RESOLVES when it occurs on a non-prose line of any tracked file, as
itself or as the head of a longer identifier -- `CARGO_BIN_EXE` is carried by
`env!("CARGO_BIN_EXE_wz-analyze")`, and a prose sentence naming the family is
naming something real.

## Why the ATOMIC STORE counts as prose, which is not a detail

`docs/.atomic/workspace.atomic.json` is the ledger: every round writes its
findings into it, in sentences, wrapped in JSON. Counted as code it would
resolve every name any round ever discussed -- including, on the very next
append, the one this round was opened to remove. A gate that its own round's
ledger entry switches off is worse than no gate, because it reports green.
Measured while building this: `WZ_C1BC_REQUIRE`, whose entire defect was that
nothing in the tree reads it, resolved through the ledger and nowhere else.

## The residue is CLASSIFIED, and unclassified is RED

Deriving the population refuted the assumption it was opened with. Not every
unresolved name is a false claim: measured on 2026-09-01, 168 names were
spelled as code in tooling prose and EIGHT resolved nowhere. ONE was the
defect, and removing it is what leaves the 167 this gate reports. Four name
something the sentence itself is saying does not exist -- an example of a
typo'd catalog tag, an example flag, a wrapper somebody might write one day,
and R2247's own finding quoted by the gate that found it. Three are FOREIGN:
`RTLD_LOCAL` belongs to a dynamic loader, `DT_SONAME` to the ELF format and
`SCE_WORKSPACE_ROOT` to a code generator this tree runs, and the tree talks to
all three without ever spelling them.

So the verdict is a classification, and `ABSENT` is where a name that does not
resolve says which kind it is. An unclassified one FAILs. The table is judged
back, so that it cannot become the place findings go to be forgotten:

  * a row whose name now RESOLVES fails -- the exemption outlived its reason;
  * a row's paths must EQUAL the files whose prose names it, so a second file
    picking up the same name is a new finding rather than a covered one;
  * `foreign` must name the OWNER and that owner must itself be live in
    non-prose -- `readelf` is a program this file's neighbour actually runs,
    `libloading` is a crate in the lockfile. A foreign name excuses itself only
    where the tree really talks to that foreigner.

STILL NOT JUDGED, stated rather than implied: which of the two kinds a row
carries. `hypothetical` is judged by the pin and by absence, not by the mood of
the sentence, and no derivation here separates a sentence whose SUBJECT is that
a name does not exist from one that wrongly says it does. Both shapes are in
this tree today and they landed differently on purpose: the census paragraph
asserted a word list was doing the deciding, so the PROSE was repaired, while
`armed_skip_guard.py` quotes `WZ_C1BC_REQUIRE` precisely to say nothing reads
it, so it is a row. That residue is open-debt item 601 rather than a silence.

## TOOLING prose, and ONE axis of Rust prose

The first subject is `scripts/**`, `.githooks/**`, `.github/**` -- prose about
this tree's own machinery, where a name spelled as code is a claim about the
tree.

Rust prose under `crates/**` is a different subject, and R2251b (open-debt item
602) measured what R2250 had only assumed. Re-derived with the rule this file
actually uses: 1020 names spelled as code there and 151 resolving nowhere --
not the 739 / 65 filed from a narrower prototype, and 85% carried rather than
"mostly foreign". Many of the 151 ARE foreign (libc, Win32, ELF: AF_LINK,
CMSG_SPACE), and deciding those needs an upstream checkout this repository
cannot promise -- zenoh-pico is a SUBMODULE, one gitlink to `git ls-files` and
empty in a clone made without `--recursive`, while zenoh-c is not vendored at
all. A gate whose oracle may be absent skips, and a skip that prints green is
the class item 598 closed.

So this file takes the axis that needs NO oracle, because the question turns
around: not "does upstream have this name" but "do WE". This tree reimplements
the zenoh-c / zenoh-pico C API and its own prose spells 152 of that API's
names, carrying 109. The 43 it does not carry are held as a SET, and each is
either a constant we have yet to provide or a sentence naming something that
was never here. What remains -- the libc / Win32 / ELF names, and our own dead
identifiers among the rest -- is open-debt item 604.

## An empty population FAILs

Every assertion here is about a set, and an empty set agrees with all of them.
If the last code span ever to appear in tooling prose is deleted, this floor
comes down in the commit that deleted it.
"""

from __future__ import annotations

import argparse
import ast
import io
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import tokenize

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: A code span. It may WRAP: prose is filled to a column and a span that began
#: on one line finishes on the next, so the population is read from a run of
#: consecutive prose lines joined back together rather than from a line.
CODE_SPAN = re.compile(r"`([^`]{1,160})`")

#: The identifier shapes a code span can be read as a NAME in. An UPPER_SNAKE
#: constant needs at least one underscore -- `SKIP` and `FAIL` are words this
#: tree's prose uses as words.
CONST = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
CALL = re.compile(r"^([a-z_][a-z0-9_]{2,})\(\)$")
BRACED = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
ASSIGNED = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=\S*$")

#: Prose by language. `.json` is here because the atomic store is a ledger of
#: sentences; see the header.
ALL_PROSE_SUFFIX = (".md", ".txt", ".json")
HASH_SUFFIX = (".sh", ".yml", ".yaml", ".toml", ".cfg")
SLASH_SUFFIX = (".rs", ".c", ".h", ".cpp", ".hpp")

#: The prose whose names are CLAIMS about this tree: its own tooling.
TOOLING = (
    ("scripts/", (".py", ".sh")),
    (".githooks/", None),
    (".github/", (".yml", ".yaml")),
)

KINDS = ("foreign", "hypothetical")

#: Names spelled as code in tooling prose that this tree does not carry, and
#: the reason that is correct. `paths` must EQUAL the files whose prose names
#: it; `owner` is required for `foreign` and must itself be live in non-prose.
ABSENT: dict[str, tuple[str, str | None, tuple[str, ...]]] = {
    # An example of a head token that is tag-SHAPED and not in the closed set,
    # which is the case that paragraph exists to separate from "no tag".
    "BEYOND_PICO": ("hypothetical", None, ("scripts/audit-catalog-status.sh",)),
    # The ELF dynamic tag. The gate beside this row runs `readelf -d` and reads
    # the SONAME out of its output; nothing in the tree spells the tag.
    "DT_SONAME": (
        "foreign",
        "readelf",
        (
            "scripts/lib/cdylib_soname_gate.py",
            "scripts/lib/prose_named_identifier_gate.py",
        ),
    ),
    # The dlopen flag that keeps two `z_*` symbol sets apart. The loader is
    # reached through the crate, which is what the lockfile carries.
    "RTLD_LOCAL": (
        "foreign",
        "libloading",
        (
            "scripts/lib/crossimpl_corpus.py",
            "scripts/lib/prose_named_identifier_gate.py",
        ),
    ),
    # sce-codegen's own environment variable, read by a program this tree runs
    # and never by this tree.
    "SCE_WORKSPACE_ROOT": (
        "foreign",
        "sce-codegen",
        (
            "scripts/lib/prose_named_identifier_gate.py",
            "scripts/verify-codegen.sh",
        ),
    ),
    # R2247's finding, quoted by the gate that found it: run-ci.sh claimed this
    # flag turned a skip into a failure and no such name was ever read. The
    # sentence is TRUE and its subject is the absence -- which is the half this
    # gate cannot tell from a false claim, and is open-debt item 601.
    "WZ_C1BC_REQUIRE": (
        "hypothetical",
        None,
        (
            "scripts/lib/armed_skip_guard.py",
            "scripts/lib/prose_named_identifier_gate.py",
        ),
    ),
    # An example flag, named in a sentence about names of nothing.
    "WZ_X_REQUIRE": ("hypothetical", None, ("scripts/lib/armed_skip_guard.py",)),
    # A wrapper nobody has written; the sentence is about what would happen to
    # the call-graph resolution if somebody did.
    "spawn_wz_ap_demo": ("hypothetical", None, ("scripts/lib/crossimpl_corpus.py",)),
}


#: R2251b (open-debt item 602). Rust prose under `crates/**` is a DIFFERENT
#: subject from tooling prose, and one axis of it is decidable with no upstream
#: checkout at all -- because the question is not "does upstream have this
#: name" but "do WE". wz reimplements the zenoh-c / zenoh-pico C API, so a
#: constant of that API named in our own prose and absent from our own tree is
#: a fact worth holding: either a constant we have not carried, or prose naming
#: something that was never there.
#:
#: The prefixes are DECLARED and then JUDGED: one with no carried member names
#: nothing this tree implements and is refused. `ZP_` was refused on the first
#: run and correctly -- its only occurrence is a CMake variable in a build
#: script, not an API constant.
UPSTREAM_PREFIXES = ("Z_", "ZC_", "ZENOH_")

#: The SET, pinned, not a count. A count would be a ceiling to ratchet; a set
#: fails in BOTH directions and names which way. A name ENTERING it means our
#: prose started citing an upstream constant we do not provide; a name LEAVING
#: it means we implemented it or the sentence went, and the pin comes down in
#: that same commit. Derived on 2026-09-01 from 152 upstream-family names in
#: Rust prose, of which 109 are carried.
UPSTREAM_UNCARRIED = frozenset(
    {
        "ZC_LOCALITY_DEFAULT",
        "ZENOH_COMPILER_CLANG",
        "ZENOH_COMPILER_GCC",
        "ZENOH_RUNTIME",
        "Z_BATCH_MULTICAST_SIZE",
        "Z_CONFIG_MULTICAST_IPV4_ADDRESS_KEY",
        "Z_CONFIG_MULTICAST_LOCATOR_DEFAULT",
        "Z_CONFIG_SCOUTING_TIMEOUT_DEFAULT",
        "Z_CONFIG_SCOUTING_WHAT_DEFAULT",
        "Z_CONGESTION_CONTROL_DEFAULT",
        "Z_FEATURE_BATCHING",
        "Z_FEATURE_CONNECTIVITY",
        "Z_FEATURE_ENCODING_VALUES",
        "Z_FEATURE_FRAGMENTATION",
        "Z_FEATURE_LIVELINESS",
        "Z_FEATURE_MATCHING",
        "Z_FEATURE_MULTICAST_DECLARATIONS",
        "Z_FEATURE_PUBLICATION",
        "Z_FEATURE_QUERYABLE",
        "Z_FEATURE_SUBSCRIPTION",
        "Z_FRAG_MAX_SIZE",
        "Z_JOIN_INTERVAL",
        "Z_KEYEXPR_CANON_CONTAINS_SHARP_OR_QMARK",
        "Z_KEYEXPR_CANON_CONTAINS_UNBOUND_DOLLAR",
        "Z_KEYEXPR_CANON_DOLLAR_AFTER_DOLLAR_OR_STAR",
        "Z_KEYEXPR_CANON_EMPTY_CHUNK",
        "Z_KEYEXPR_CANON_LONE_DOLLAR_STAR",
        "Z_KEYEXPR_CANON_STARS_IN_CHUNK",
        "Z_KEYEXPR_CANON_SUCCESS",
        "Z_LINK_CAP_FLOW_DATAGRAM",
        "Z_LINK_CAP_TRANSPORT_RAWETH",
        "Z_LINK_CAP_TRANSPORT_UNICAST",
        "Z_LISTEN_MAX_CONNECTION_NB",
        "Z_LOCALITY_ANY",
        "Z_LOCALITY_REMOTE",
        "Z_LOCALITY_SESSION_LOCAL",
        "Z_QUERY_TARGET_DEFAULT",
        "Z_REPLY_KEYEXPR_DEFAULT",
        "Z_SAMPLE_KIND_DEFAULT",
        "Z_SELECTOR_QUERY_MATCH",
        "Z_SELECTOR_TIME",
        "Z_TRANSPORT_LEASE_EXPIRE_FACTOR",
        "Z_ZID_LENGTH",
    }
)


def tracked(root: pathlib.Path | None) -> list[str]:
    if root is None:
        out = subprocess.run(
            ["git", "ls-files"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        return out
    base = root
    return sorted(
        str(p.relative_to(base))
        for p in base.rglob("*")
        if p.is_file() and ".git" not in p.parts
    )


def is_tooling(rel: str) -> bool:
    for prefix, suffixes in TOOLING:
        if not rel.startswith(prefix):
            continue
        if suffixes is None:
            return True
        if rel.endswith(suffixes):
            return True
    return False


def python_prose(text: str) -> set[int]:
    """`#` comments plus the docstrings `ast` reports -- NOT every string.

    A string literal that is a VALUE is code: an environment name lives in
    `os.environ.get("...")` and a fixture body is a fixture, and reading either
    as prose would take a real occurrence away from the resolution side.
    """
    lines: set[int] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                lines.add(tok.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return lines
    holders = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    for node in ast.walk(tree):
        if not isinstance(node, holders):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if not isinstance(first, ast.Expr):
            continue
        value = first.value
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            continue
        for number in range(value.lineno, (value.end_lineno or value.lineno) + 1):
            lines.add(number)
    return lines


def span_name(span: str) -> str | None:
    """The NAME a code span spells, or None when the span is a QUOTATION.

    A span that is exactly one identifier -- optionally `$`-sigilled, optionally
    with the `=value` an environment arming is written with -- asserts that the
    name exists. A span holding a command, an expression or a quoted string is
    a quotation, and a quotation may legitimately quote something that was
    removed: `run-ci.sh` used to be quoted as `|| { ::warning; SOMETHING=1 }`
    long after that fallback went. The line is between what the prose SPELLS
    and what it QUOTES, and it is decided by the span's shape rather than by
    the sentence around it, for the reason `unclassifiable()` in
    `armed_oracle_census.py` gives about word lists.
    """
    text = re.sub(r"\s+", " ", span).strip()
    braced = BRACED.match(text)
    if braced:
        text = braced.group(1)
    elif text.startswith("$"):
        text = text[1:]
    assigned = ASSIGNED.match(text)
    if assigned:
        text = assigned.group(1)
    if CONST.match(text):
        return text
    call = CALL.match(text)
    if call:
        return call.group(1)
    return None


#: Module-level assignments in THIS file whose CONTENT is pinned data: names
#: this gate records as absent, and fixture bodies that spell names on purpose.
#: Their line spans do not resolve anything -- see `Tree.carries`.
PINNED_DATA = (
    "ABSENT",
    "UPSTREAM_UNCARRIED",
    "FIXTURES",
    "BASE_UPSTREAM",
    "BASE_TOOLING",
    "FIXTURE_PINS",
)


def pinned_data_lines(text: str) -> set[int]:
    """Line numbers covered by this file's `PINNED_DATA` assignments."""
    lines: set[int] = set()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return lines
    for node in tree.body:
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Name) and target.id in PINNED_DATA:
                end = node.end_lineno or node.lineno
                lines.update(range(node.lineno, end + 1))
    return lines


def prose_lines(rel: str, text: str) -> set[int]:
    body = text.split("\n")
    suffix = os.path.splitext(rel)[1]
    if suffix == ".py":
        return python_prose(text)
    if suffix in ALL_PROSE_SUFFIX:
        return set(range(1, len(body) + 1))
    if suffix in HASH_SUFFIX or (rel.startswith(".githooks/") and suffix == ""):
        return {n for n, line in enumerate(body, 1) if line.lstrip().startswith("#")}
    if suffix in SLASH_SUFFIX:
        return {
            n
            for n, line in enumerate(body, 1)
            if line.lstrip().startswith(("//", "*", "/*"))
        }
    return set()


class Tree:
    """The tracked files, read once, split into prose lines and code lines."""

    def __init__(self, root: pathlib.Path | None) -> None:
        self.root = ROOT if root is None else root
        self.files = tracked(root)
        self._cache: dict[str, tuple[list[str], set[int], set[int]]] = {}

    def read(self, rel: str) -> tuple[list[str], set[int]]:
        """`(lines, PROSE lines)` -- the population side."""
        if rel not in self._cache:
            try:
                text = (self.root / rel).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                text = ""
            pinned: set[int] = set()
            if (self.root / rel).resolve() == pathlib.Path(__file__).resolve():
                pinned = pinned_data_lines(text)
            self._cache[rel] = (text.split("\n"), prose_lines(rel, text), pinned)
        body, prose, _ = self._cache[rel]
        return body, prose

    def non_resolving(self, rel: str) -> set[int]:
        """Lines that cannot RESOLVE a name: prose, plus this file's pinned data.

        Two different sets on purpose. Prose is where a name is CLAIMED, so it
        feeds the population; pinned data is neither claim nor evidence, so it
        feeds only this one. Merging them put the fixture bodies into the
        population and reported six selftest names as dangling.
        """
        self.read(rel)
        _, prose, pinned = self._cache[rel]
        return prose | pinned

    def prose_runs(self, rel: str) -> list[str]:
        """Maximal runs of consecutive prose lines, joined back into text."""
        body, prose = self.read(rel)
        runs: list[str] = []
        current: list[str] = []
        for number, line in enumerate(body, 1):
            if number in prose:
                current.append(line)
            elif current:
                runs.append("\n".join(current))
                current = []
        if current:
            runs.append("\n".join(current))
        return runs

    def named(self) -> dict[str, set[str]]:
        """`name -> the tooling files whose PROSE spells it as code`."""
        out: dict[str, set[str]] = {}
        for rel in self.files:
            if not is_tooling(rel):
                continue
            for run in self.prose_runs(rel):
                for match in CODE_SPAN.finditer(run):
                    name = span_name(match.group(1))
                    if name is not None:
                        out.setdefault(name, set()).add(rel)
        return out

    def rust_named(self) -> dict[str, set[str]]:
        """`name -> the crates/** Rust files whose PROSE spells it as code`.

        Same span rule as `named()`; a different subject. Rust prose cites a
        foreign API on purpose all day, so only the upstream families this tree
        reimplements are read from it -- see `UPSTREAM_PREFIXES`.
        """
        out: dict[str, set[str]] = {}
        for rel in self.files:
            if not (rel.startswith("crates/") and rel.endswith(".rs")):
                continue
            for run in self.prose_runs(rel):
                for match in CODE_SPAN.finditer(run):
                    name = span_name(match.group(1))
                    if name is not None and name.startswith(UPSTREAM_PREFIXES):
                        out.setdefault(name, set()).add(rel)
        return out

    def carries(self, name: str) -> bool:
        """The name, or a longer identifier it heads, on a non-prose line.

        THIS FILE's PINNED DATA is not part of the universe. Its tables spell
        every name they classify, in keys and in set members, and its fixtures
        spell more -- all of them in code position. Counted, the gate would
        resolve every absence it exists to record, starting with the row it was
        written for; R2250 saw all seven `ABSENT` rows go red at once the moment
        the file was staged, for exactly that reason.
        ⚠ R2251b narrowed this from "skip the whole file", which was too much:
        it made the gate's own prose unable to name its own constants, and
        `UPSTREAM_PREFIXES` reported as a dangling name the instant it was
        documented. What must not resolve is the pinned DATA, not the code that
        reads it -- see `PINNED_DATA`.
        """
        pattern = re.compile(r"\b" + re.escape(name) + r"(?:_[A-Za-z0-9]+)*\b")
        for rel in self._grep_files(name):
            body, _ = self.read(rel)
            skip = self.non_resolving(rel)
            for number, line in enumerate(body, 1):
                if number in skip:
                    continue
                if pattern.search(line):
                    return True
        return False

    def _grep_files(self, needle: str) -> list[str]:
        if self.root is ROOT:
            proc = subprocess.run(
                ["git", "grep", "-l", "-I", "-F", needle],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            if proc.returncode not in (0, 1):
                raise RuntimeError(f"git grep failed for {needle}: {proc.stderr}")
            return proc.stdout.split()
        return self.files


def upstream_findings(tree: "Tree") -> tuple[list[str], int, int]:
    """The upstream-family axis: `(findings, family size, uncarried size)`."""
    named = tree.rust_named()
    findings: list[str] = []
    if not named:
        findings.append(
            "no upstream-family name is spelled as code in any Rust prose. This "
            "tree reimplements that API and its own comments cite it constantly, "
            "so an empty population is a broken derivation, not a clean result"
        )
        return findings, 0, 0

    for prefix in UPSTREAM_PREFIXES:
        members = [n for n in named if n.startswith(prefix)]
        if not any(tree.carries(n) for n in members):
            findings.append(
                f"prefix `{prefix}` has no CARRIED member among the "
                f"{len(members)} name(s) our prose spells with it, so it names "
                f"nothing this tree implements and is not an upstream family "
                f"this axis can speak about -- drop it, or carry one"
            )

    uncarried = {n for n in named if not tree.carries(n)}
    entered = sorted(uncarried - UPSTREAM_UNCARRIED)
    left = sorted(UPSTREAM_UNCARRIED - uncarried)
    for name in entered:
        where = ", ".join(sorted(named[name])[:2])
        findings.append(
            f"{where}: our prose cites upstream `{name}` and this tree does not "
            f"carry it. Either provide it, or stop naming it as ours. If it is "
            f"deliberately absent, add it to UPSTREAM_UNCARRIED in this commit "
            f"so the set stays the record of what we do not provide"
        )
    for name in left:
        findings.append(
            f"UPSTREAM_UNCARRIED pins `{name}` and it is no longer uncarried -- "
            f"this tree now provides it, or the sentence citing it went. Take it "
            f"out of the set in the same commit; a pin that outlives its reason "
            f"is how a set becomes a list nobody reads"
        )
    return findings, len(named), len(uncarried)


def check(root: pathlib.Path | None = None) -> int:
    tree = Tree(root)
    named = tree.named()
    findings: list[str] = []

    if not named:
        print(
            "prose-name gate FAIL: no code span in any tooling prose. An empty "
            "population agrees with every rule here, so it is a floor and not "
            "a pass -- if the last one really went, this gate goes in the same "
            "commit.",
            file=sys.stderr,
        )
        return 1

    unresolved: dict[str, set[str]] = {}
    for name, paths in named.items():
        if not tree.carries(name):
            unresolved[name] = paths

    for name in sorted(unresolved):
        if name in ABSENT:
            continue
        where = ", ".join(sorted(unresolved[name]))
        findings.append(
            f"{where}: prose spells `{name}` as code and nothing in this tree "
            f"carries that name. A discarded design that survives as a name "
            f"sends the next reader looking for it, or is read as evidence "
            f"that something is handled. Make the name real, describe what the "
            f"code actually does, or classify it in ABSENT."
        )

    for name in sorted(ABSENT):
        kind, owner, paths = ABSENT[name]
        if kind not in KINDS:
            findings.append(
                f"ABSENT[{name}] declares kind `{kind}`, which is not one of "
                f"{KINDS}. An unclassified row is a FAIL, not a pass."
            )
            continue
        if name not in named:
            findings.append(
                f"ABSENT[{name}] is declared but no tooling prose spells that "
                f"name any more. Drop the row in the commit that dropped the "
                f"sentence."
            )
            continue
        if name not in unresolved:
            findings.append(
                f"ABSENT[{name}] says this tree does not carry the name, and "
                f"it now does. The row outlived its reason -- drop it."
            )
            continue
        if set(paths) != named[name]:
            findings.append(
                f"ABSENT[{name}] pins {sorted(paths)} and the prose naming it "
                f"is {sorted(named[name])}. A second file picking up the name "
                f"is a new claim, not a covered one."
            )
        if kind == "foreign":
            if not owner:
                findings.append(
                    f"ABSENT[{name}] is `foreign` and names no owner. A "
                    f"foreign name excuses itself by the foreigner this tree "
                    f"actually talks to."
                )
            elif not tree.carries(owner):
                findings.append(
                    f"ABSENT[{name}] is `foreign` to `{owner}`, and `{owner}` "
                    f"occurs nowhere in this tree outside prose. Then the tree "
                    f"does not talk to it and the row is prose about prose."
                )
        elif owner is not None:
            findings.append(
                f"ABSENT[{name}] is `{kind}` and names an owner. Only "
                f"`foreign` carries one."
            )

    upstream, family, uncarried_count = upstream_findings(tree)
    findings.extend(upstream)

    if findings:
        for line in findings:
            print(f"prose-name gate FAIL: {line}", file=sys.stderr)
        return 1

    print(
        f"prose-name: OK -- {len(named)} name(s) spelled as code in tooling "
        f"prose; {len(named) - len(unresolved)} carried by this tree, "
        f"{len(ABSENT)} classified absent ("
        f"{sum(1 for k, _, _ in ABSENT.values() if k == 'foreign')} foreign, "
        f"{sum(1 for k, _, _ in ABSENT.values() if k == 'hypothetical')} "
        f"hypothetical). Rust prose cites {family} upstream-family name(s); "
        f"{family - uncarried_count} carried, {uncarried_count} pinned as not "
        f"provided by this tree."
    )
    return 0


#: Fixtures drive BOTH directions. `claim` is the exact shape item 600 was
#: filed for -- a docstring naming a constant its own module never defines.
#: `good` is the control and must PASS, so a gate that simply reds is not
#: mistaken for one that discriminates; it also carries the two shapes an
#: earlier draft of this file got WRONG, and would have swallowed: a name
#: carried only by a value-position string literal, and a name carried only as
#: the head of a longer identifier.
FIXTURES: dict[str, tuple[dict[str, str], bool]] = {
    "claim": (
        {
            "scripts/lib/g.py": '''\
"""A gate whose prose names `SELFTEST_ONLY_ALPHA`, which it does not have."""


def rule(line):
    return line.startswith("#")
''',
        },
        False,
    ),
    "good": (
        {
            "scripts/lib/g.py": '''\
"""A gate whose prose names `SELFTEST_ONLY_BETA` and `rule()`.

The environment name `SELFTEST_ONLY_GAMMA` is carried by a value-position
string below, and `SELFTEST_ONLY_DELTA` only as the head of a longer one.
"""

import os

SELFTEST_ONLY_BETA = 1


def rule(line):
    if os.environ.get("SELFTEST_ONLY_GAMMA"):
        return SELFTEST_ONLY_DELTA_WIDE
    return line.startswith("#")


SELFTEST_ONLY_DELTA_WIDE = 2
''',
        },
        True,
    ),
    "ledger-rescue": (
        {
            "scripts/lib/g.py": '''\
"""A gate whose prose names `SELFTEST_ONLY_ALPHA`, which it does not have."""


def rule(line):
    return line.startswith("#")
''',
            "docs/.atomic/workspace.atomic.json": (
                '{"entry": "the round that removed `SELFTEST_ONLY_ALPHA` from '
                'the docstring"}\n'
            ),
        },
        False,
    ),
    "empty": (
        {
            "scripts/lib/g.py": '''\
"""A gate whose prose names nothing at all."""


def rule(line):
    return line.startswith("#")
''',
        },
        False,
    ),
    "shell-claim": (
        {
            "scripts/run.sh": """\
#!/usr/bin/env bash
# The lane arms `WZ_SELFTEST_ONLY_REQUIRE=1` and turns a skip into a failure.
echo hello
""",
        },
        False,
    ),
    "shell-carried": (
        {
            "scripts/run.sh": """\
#!/usr/bin/env bash
# The lane arms `WZ_SELFTEST_ONLY_REQUIRE=1` and turns a skip into a failure.
WZ_SELFTEST_ONLY_REQUIRE=1 echo hello
""",
        },
        True,
    ),
    "md-does-not-rescue": (
        {
            "scripts/run.sh": """\
#!/usr/bin/env bash
# The lane arms `WZ_SELFTEST_ONLY_REQUIRE=1` and turns a skip into a failure.
echo hello
""",
            "README.md": "`WZ_SELFTEST_ONLY_REQUIRE` is documented here.\n",
        },
        False,
    ),
    # R2251b (item 602), the upstream axis. `upstream-pinned` is the state the
    # tree is actually in: our prose cites a constant we do not carry, and the
    # pin is the record of that. `upstream-unpinned` is the same prose with an
    # empty pin, which must FAIL -- that is a name entering the set unrecorded.
    "upstream-pinned": (
        {
            "crates/y/src/lib.rs": "//! Upstream has `Z_SELFTEST_MISSING`; we do not.\n"
            "pub fn f() {}\n",
        },
        True,
    ),
    "upstream-unpinned": (
        {
            "crates/y/src/lib.rs": "//! Upstream has `Z_SELFTEST_MISSING`; we do not.\n"
            "pub fn f() {}\n",
        },
        False,
    ),
    # A pin whose reason went: nothing cites the name any more.
    "upstream-pin-outlived": ({}, False),
    # The floor. No Rust prose cites the API this tree reimplements, which
    # cannot be true of this tree and must not read as clean.
    "upstream-empty": (
        {
            "scripts/lib/g.py": '''\
"""A gate whose prose names `rule()`."""


def rule(line):
    return line.startswith("#")
''',
        },
        False,
    ),
    "out-of-scope-prose": (
        {
            "crates/x/src/lib.rs": "//! Upstream calls this `AF_SELFTEST_ONLY`.\n"
            "pub fn f() {}\n",
            "scripts/lib/g.py": '''\
"""A gate whose prose names `rule()`."""


def rule(line):
    return line.startswith("#")
''',
        },
        True,
    ),
}


#: Written into every fixture root except the case that is ABOUT an empty
#: upstream population: one upstream-family name our prose cites and our code
#: carries, so the axis has a population to be right about.
BASE_UPSTREAM = {
    "crates/base/src/lib.rs": (
        "//! Ours mirrors upstream `Z_SELFTEST_CARRIED`, `ZC_SELFTEST_CARRIED`\n"
        "//! and `ZENOH_SELFTEST_CARRIED` -- one per declared prefix, because a\n"
        "//! prefix with no carried member is refused and a fixture that omits\n"
        "//! one would be testing that refusal instead of the axis.\n"
        "pub const Z_SELFTEST_CARRIED: u8 = 1;\n"
        "pub const ZC_SELFTEST_CARRIED: u8 = 2;\n"
        "pub const ZENOH_SELFTEST_CARRIED: u8 = 3;\n"
    ),
}

#: The upstream pin each fixture runs under; absent means the empty set.
FIXTURE_PINS = {
    "upstream-pinned": frozenset({"Z_SELFTEST_MISSING"}),
    "upstream-pin-outlived": frozenset({"Z_SELFTEST_GHOST"}),
}

#: A tooling file for every fixture, for the same reason: both floors are
#: unconditional, so a case about one axis must still satisfy the other.
BASE_TOOLING = {
    "scripts/lib/base.py": '''\
"""A gate whose prose names `rule()`, which it has."""


def rule(line):
    return line.startswith("#")
''',
}

#: Which base a case must NOT get, because that empty population IS the case.
FIXTURE_NO_BASE = {"upstream-empty": "upstream", "empty": "tooling"}


def selftest() -> int:
    global UPSTREAM_UNCARRIED
    bad = 0
    saved = dict(ABSENT)
    saved_pin = UPSTREAM_UNCARRIED
    ABSENT.clear()
    try:
        for name, (files, want_pass) in sorted(FIXTURES.items()):
            UPSTREAM_UNCARRIED = FIXTURE_PINS.get(name, frozenset())
            omit = FIXTURE_NO_BASE.get(name)
            base: dict[str, str] = {}
            if omit != "upstream":
                base.update(BASE_UPSTREAM)
            if omit != "tooling":
                base.update(BASE_TOOLING)
            files = {**base, **files}
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                for rel, body in files.items():
                    path = root / rel
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(body, encoding="utf-8")
                rc = check(root=root)
            ok = (rc == 0) == want_pass
            print(
                f"prose-name selftest {name}: rc={rc} "
                f"want={'pass' if want_pass else 'fail'} "
                f"{'ok' if ok else 'WRONG'}"
            )
            if not ok:
                bad = 1
    finally:
        ABSENT.update(saved)
        UPSTREAM_UNCARRIED = saved_pin
    return bad


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="prose-named identifier gate")
    parser.add_argument("--check", action="store_true", help="walk this tree")
    parser.add_argument("--selftest", action="store_true", help="drive fixtures")
    args = parser.parse_args(argv)
    if args.check == args.selftest:
        parser.error("pass exactly one of --check / --selftest")
    # An `if` STATEMENT, not a conditional expression: `gate_reason_claims.py`
    # seeds the selftest call closure from the branch, so the expression form
    # leaves it empty and this file's fixture tables get graded as reason
    # tables whose backticks must resolve. Written the way the tree's own
    # classifier can derive it.
    if args.selftest:
        return selftest()
    return check()


if __name__ == "__main__":
    sys.exit(main())
