#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2192 (no register item) — A DEPENDENCY THIS TREE'S PROSE NAMES IS ONE
`cargo metadata` RESOLVES, AND A DEPENDENCY IT DENIES IS ONE THAT RESOLVES TO
NOTHING.

## Why the citation says no item while the file answers for one

The debt this answers, 530, lives in the register half that is NOT the store,
so there is no `debt-` id to cite and the provenance convention's explicit
declaration is the only true one available. Its sibling `prose_feature_gate.py`
stands in the same place for the same reason. The item is named below in full
instead, which is what a reader grepping for it will find.

## The item, and which half of it this is

Item 530 is "prose that contradicts a DERIVED fact has no instrument". It had
two measured cases and R2190 built the instrument for the second (a cargo
invocation naming features that exist). This is the instrument for the FIRST,
which R2190 explicitly left open and told the next round to take:

    R2105 — `scripts/run-ci.sh` and `xtask/src/main.rs` both said a plain build
    of the wz stack wanted no native XML toolchain, while the resolve graph
    reached that crate through the SCE forge runtime's own build script, and
    the `portability` job said the right thing in its own comment. The tree
    contradicted itself and the consumer who hit the wall believed the wrong
    half.

R2190's note recorded the shape that worked and the shape that does not, and
this file is the first one applied to the graph:

    FIND THE FORM PROSE ALREADY USES. Do not ask anyone to mark anything.

## The two forms, both derived from the tree rather than invented for it

Measured over every tracked file: this tree states a dependency in exactly two
syntactic ways, and both name their two crates in the sentence.

  ARM 1 — an English dependency clause: a ticked name, a dependency verb (in
  its plain, build- and dev- spellings), and a second ticked name.

  ARM 2 — an arrow written straight after a ticked name, pointing at the next
  ticked name. This is how a build-script chain gets written down.

Neither is a marker. Nobody wrote either of them to be read by a gate, which
is the whole point: a form that has to be applied is a form unmarked prose
walks past, and open-debt item 526's block was rejected as this item's
candidate for exactly that reason.

## BOTH POLARITIES, which is what makes it the FIRST case's instrument

The measured defect was a DENIAL — prose saying a dependency was not there.
So a claim carrying a negation inside its clause is adjudicated the other way
round. Two live denials are in the tree today and both are true, and a gate
that only checked assertions would have had nothing to say about the sentence
that started this item.

THE TWO POLARITIES MEASURE DIFFERENT RELATIONS, and the asymmetry is the whole
point rather than an oversight:

  * An ASSERTION is held to a DIRECT edge. Measured over every site in this
    tree, that is what an arrow chain and a dependency clause here state, and
    loosening it to reachability would make "it goes through here" true of
    almost any pair in a workspace this size.

  * A DENIAL is held to REACHABILITY. "Does not depend on" is only true if
    NOTHING carries it, and a denial checked against direct edges alone passes
    exactly the sentence this item was opened for: a build was said to want no
    native XML toolchain while the crate that wants one hung two hops down a
    build-script chain. Direct-edge checking would have called that denial
    true. Measured today: the workspace facade reaches that crate, so the
    original claim written in this form goes RED, and the two denials actually
    in the tree are unreachable and stay green.

The two floors are separate from each other and from the arrow arm's, for the
reason R2137 records: a total says nothing about which subset went to zero,
and the subset that matters here is the one the item was opened for.

## NOT a phrase list, which item 530 measured rather than argued

A gate forbidding the sentence that was wrong would red the commit that
EXPLAINS it was wrong — R2105's own repair quotes the false clause in order to
retract it, in both files, and R2161 quoted a retired spelling three times to
describe a rename. Prose that describes an error correctly and prose that IS
the error are indistinguishable to a string ban. So what is adjudicated is a
FORM against a DERIVATION, and a retraction that names no two crates in one
clause is simply not a claim this gate has an opinion about.

## Unclassified is a FAIL, in both directions

A site whose subject or object this gate cannot fix — a pronoun, a relative
clause, a name the graph does not carry — is NOT waved through. It has to be
declared with the reason, and a declaration that no longer matches a site is
also a FAIL, so the list cannot rot into a permission slip. That is the shape
`prose_feature_gate.py` and `ext_name::DECLARED_EMPTY` already use here.

Three discriminators were added after the scan got a site WRONG, and each one
is a real sentence in this tree rather than a hypothetical: a subject fixed by
a pronoun after a full stop, an object introduced by a relative clause whose
head is not ticked, and a name that is not a package in this graph at all. The
first two both read as confident findings before they were read by hand.

## What is out of the population, and why that is a rule

`docs/.atomic/**` is the frozen audit ledger. Rewriting an entry to follow a
graph change is this workspace's own named anti-pattern, so an entry naming an
edge that has since gone is CORRECT and stays. A gate that made the store a
subject would demand the exact edit the store forbids.

## The stated limit, so the green is not read wider than it is

The subject is the WORKSPACE GRAPH: what `cargo metadata --all-features`
resolves. A claim about a native system library rather than a crate is not in
this population — that fact is derived by `apt_package_census.py`'s shortfall
arm and carried by README's build-prerequisites block, which is where R2105's
repair put it. What this gate adds is the half nobody held: the CRATE claim,
in both polarities, wherever prose makes one.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"

# A leading comment marker, so a run of comment lines folds into the one
# paragraph the sentence was written as. A quoted command or clause routinely
# wraps across three of them, and a line-at-a-time scan reads half a claim.
MARKER = re.compile(r"^[ \t]*(?://!|///|//|#|\*/|\*|--)[ \t]?")

NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
TICKED = "`(" + NAME + ")`"

# ARM 1. Subject, a short span, a dependency verb, a short span, object.
CLAUSE = re.compile(
    TICKED + r"([^`\n]{0,80}?)\b(?:build-|dev-)?depends?\s+(?:on|upon)\b"
    r"([^`\n]{0,50}?)(?=" + TICKED + r")"
)

# ARM 2. An arrow straight after a ticked name. Only whitespace and an opening
# bracket may sit between, because once a WORD does the arrow is part of a
# sentence rather than a chain, and widening this window was measured to move
# which pair a match reports.
ARROW = re.compile(TICKED + r"[\s(]*->\s*(?:the\s+)?(?=`?(" + NAME + r")`?)")

# A span that stops this gate fixing the subject or the object. A full stop, a
# colon, a semicolon or a dash ends the clause the ticked name was the subject
# of; a relative pronoun hands the role to a head this gate cannot resolve.
BREAKS = re.compile(r"[.;:—]|\b(?:which|that|whose|who)\b", re.IGNORECASE)

# A negation inside the clause. The claim is then that the edge is ABSENT.
NEGATION = re.compile(r"\b(?:not|never|cannot)\b", re.IGNORECASE)

# (arm, path, "<subject>-><object>") -> why this gate cannot adjudicate it.
#
# BOTH DIRECTIONS. An undeclared unresolvable site FAILS, so the population
# cannot grow in silence; a declared entry that no longer occurs FAILS too, so
# the list cannot become a permission slip nobody re-reads.
UNRESOLVED_DECLARED: dict[tuple[str, str, str], str] = {
    (
        "clause",
        "crates/wz-capi-core/Cargo.toml",
        "fresh_zid->wz",
    ): "the subject is a cargo feature, not a package this graph carries",
    (
        "clause",
        "crates/wz-capture/src/lib.rs",
        "Direction->wz-session-core",
    ): "the subject is a Rust type, not a package this graph carries",
    (
        "clause",
        "crates/wz-runtime-tokio/src/test_fixtures.rs",
        "wz-runtime-tokio-test-support->wz-runtime-tokio",
    ): (
        "the clause opens a NEW sentence whose subject is a pronoun standing "
        "for the ticked name before the full stop; the pair it resolves to is "
        "right, and it is right by luck rather than by anything this gate read"
    ),
    (
        "clause",
        "deploy/mcu-noheap-probe/Cargo.toml",
        "alloc->wz-session-core",
    ): "the subject is a cargo feature, not a package this graph carries",
    (
        "clause",
        "docs/rfc-sce-protocol-synthesis.md",
        "sce-rust-runtime->no_std",
    ): "the object is a Rust compilation mode, not a package",
    (
        "clause",
        "scripts/lib/analysis_surface_parity.py",
        "wz-analyze->wz-tls-record",
    ): (
        "a relative clause: the ticked name is the OBJECT of the denial and "
        "the subject is an unticked noun phrase, so both roles this gate needs "
        "belong to something it did not read"
    ),
    (
        "clause",
        "scripts/lib/apt_package_census.py",
        "sce-forge-runtime->sce-build",
    ): (
        "one of the two sites in this file puts a colon and a pronoun between "
        "the ticked subject and the verb; the other site states the same pair "
        "plainly and IS adjudicated"
    ),
    (
        "arrow",
        "crates/wz-integration-tests/tests/wz_router_routes_pico_interop.rs",
        "z_pub->wz",
    ): (
        "a data-flow arrow between a foreign C entry point and the ROUTER "
        "process, which shares its name with a package in this graph"
    ),
    (
        "arrow",
        "crates/wz-integration-tests/tests/wz_router_routes_pico_interop.rs",
        "z_put->wz",
    ): (
        "the same data-flow arrow, second entry point; the destination is the "
        "running router, not the facade crate"
    ),
}


def reachable(edges: set[tuple[str, str]], start: str) -> set[str]:
    """Every package `start` pulls in, at any depth. A denial is about this."""
    forward: dict[str, set[str]] = {}
    for a, b in edges:
        forward.setdefault(a, set()).add(b)
    seen: set[str] = set()
    stack = [start]
    while stack:
        for nxt in forward.get(stack.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def graph() -> tuple[set[str], set[tuple[str, str]]]:
    """(package names, declared dependency edges).

    `--all-features`, because a denial has to hold under EVERY feature
    selection to be true; adjudicating it against the default set would let a
    feature-gated dependency make a false denial pass.

    The edges are the DECLARED ones from each manifest rather than the resolve
    nodes, so a dev- or build-dependency is an edge the same way a normal one
    is -- which is the kind the measured case ran through.
    """
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features"],
        cwd=CRATES,
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(f"cargo metadata failed: {out.stderr[:400]}")
    meta = json.loads(out.stdout)
    names = {p["name"] for p in meta["packages"]}
    edges = {
        (p["name"], d["name"]) for p in meta["packages"] for d in p["dependencies"]
    }
    return names, edges


def paragraphs(text: str) -> list[tuple[str, int]]:
    """Runs of non-blank lines, comment markers stripped, joined with spaces."""
    out: list[tuple[str, int]] = []
    buf: list[str] = []
    start = 0
    for i, line in enumerate(text.split("\n"), 1):
        body = MARKER.sub("", line).strip()
        if not body:
            if buf:
                out.append((" ".join(buf), start))
                buf = []
            continue
        if not buf:
            start = i
        buf.append(body)
    if buf:
        out.append((" ".join(buf), start))
    return out


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True)
    return out.stdout.split()


def claims(para: str) -> list[tuple[str, str, str, bool, str | None]]:
    """(arm, subject, object, negated, unresolvable_reason) for one paragraph."""
    found: list[tuple[str, str, str, bool, str | None]] = []
    for m in CLAUSE.finditer(para):
        subject, mid, tail, obj = m.group(1), m.group(2), m.group(3), m.group(4)
        why = None
        if BREAKS.search(mid):
            why = "the span between the ticked subject and the verb does not fix it"
        elif BREAKS.search(tail):
            why = "the span between the verb and the ticked object does not fix it"
        found.append(("clause", subject, obj, bool(NEGATION.search(mid)), why))
    for m in ARROW.finditer(para):
        found.append(("arrow", m.group(1), m.group(2), False, None))
    return found


def scan(
    root: pathlib.Path,
    files: list[str],
    names: set[str],
    edges: set[tuple[str, str]],
) -> tuple[dict[str, int], list[str], set[tuple[str, str, str]]]:
    """(per-arm adjudicated counts, findings, unresolvable site keys)."""
    counts = {"clause+": 0, "clause-": 0, "arrow": 0}
    findings: list[str] = []
    unresolved: set[tuple[str, str, str]] = set()
    for rel in files:
        path = root / rel
        # The frozen ledger is not a subject; see the module doc.
        if rel.startswith("docs/.atomic/") or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for para, line in paragraphs(text):
            for arm, subject, obj, negated, why in claims(para):
                # Neither side is a package: the graph has no standing to read
                # this as a dependency claim at all, and a sweep that guessed
                # would report on function and type names by the hundred.
                if subject not in names and obj not in names:
                    continue
                key = (arm, rel, f"{subject}->{obj}")
                if why is None and (subject not in names or obj not in names):
                    why = "one side is not a package this workspace graph carries"
                if why is not None:
                    unresolved.add(key)
                    if key not in UNRESOLVED_DECLARED:
                        findings.append(
                            f"{rel}:{line}: a dependency claim about "
                            f"`{subject}` and `{obj}` this gate cannot "
                            f"adjudicate -- {why}. Unclassified is not a pass: "
                            f"rewrite the sentence so both roles are ticked "
                            f"package names, or declare the site in "
                            f"`UNRESOLVED_DECLARED` with the reason."
                        )
                    continue
                counts[
                    "arrow" if arm == "arrow" else ("clause-" if negated else "clause+")
                ] += 1
                direct = (subject, obj) in edges
                if negated:
                    # A denial is about REACHABILITY: nothing may carry it.
                    if obj in reachable(edges, subject):
                        how = "directly" if direct else "through a chain"
                        findings.append(
                            f"{rel}:{line}: prose says `{subject}` does not "
                            f"depend on `{obj}`, and `cargo metadata "
                            f"--all-features` reaches it {how}. Item 530's "
                            f"first measured case is a DENIAL the graph "
                            f"contradicts, and it was a chain that carried it."
                        )
                elif not direct:
                    tail = (
                        "reaches it only through a chain, so this reads as a "
                        "path summary rather than the edge it states"
                        if obj in reachable(edges, subject)
                        else "does not resolve it at all"
                    )
                    findings.append(
                        f"{rel}:{line}: prose states a dependency of "
                        f"`{subject}` on `{obj}` and `cargo metadata "
                        f"--all-features` {tail}. A path written down and "
                        f"never re-derived is prose, and this is the shape a "
                        f"derivation can adjudicate."
                    )
    return counts, findings, unresolved


def check() -> int:
    names, edges = graph()
    counts, findings, unresolved = scan(ROOT, tracked_files(), names, edges)

    # Per-arm floors, not one total. A total cannot say WHICH arm went to zero,
    # and the arm this item was opened for is the negative one.
    for arm, label in (
        ("clause+", "stated dependency"),
        ("clause-", "denied dependency"),
        ("arrow", "arrow chain"),
    ):
        if counts[arm] == 0:
            print(
                f"prose-dep-graph: FAIL -- no {label} claim in this tree, so "
                f"that arm would report clean over an empty population. If the "
                f"claims genuinely went away, lower this floor in the same "
                f"commit that removed them."
            )
            return 1

    for key, why in sorted(UNRESOLVED_DECLARED.items()):
        if key not in unresolved:
            findings.append(
                f"{key[1]}: the {key[0]} site `{key[2]}` is declared "
                f"unresolvable ({why}) and no longer occurs. A declaration "
                f"that outlives its subject is a permission slip nobody "
                f"re-reads; delete the entry."
            )

    if findings:
        print(f"prose-dep-graph: FAIL -- {len(findings)} finding(s)")
        for f in findings:
            print(f"  {f}")
        return 1
    print(
        f"prose-dep-graph: {counts['clause+']} stated + {counts['clause-']} "
        f"denied dependency claim(s) and {counts['arrow']} arrow-chain edge(s) "
        f"all agree with `cargo metadata --all-features`, "
        f"{len(UNRESOLVED_DECLARED)} site(s) declared unresolvable and all "
        f"still present"
    )
    return 0


# ASSEMBLED, NEVER SPELLED. This file is tracked, so `--check` reads it: a
# fixture written out as a literal would be scanned as production prose, which
# is how R2191's gate was green while untracked and red on its first commit.
# The pieces below cannot match either arm until they are joined at runtime.
_V = "depend" + "s on"
_A = "-" + ">"
_T = "`"


def _fixture() -> dict[str, str]:
    """Shapes an earlier build of this scanner got WRONG, plus its controls.

    The graph behind it is `alpha` -> `beta` -> `gamma`, with a fourth name
    nothing reaches. That second hop is not decoration: a denial adjudicated
    against DIRECT edges swallows a chain, which is precisely the sentence
    item 530 was opened for, so the fixture has to contain one.
    """
    a, b, c, d = (
        f"{_T}alpha{_T}",
        f"{_T}beta{_T}",
        f"{_T}gamma{_T}",
        f"{_T}delta{_T}",
    )
    return {
        # controls: a true statement, a true denial, a true dev- spelling
        "ok.md": f"{a} {_V} {b} today.\n",
        "okneg.md": f"{a} does not {_V} {d} today.\n",
        "okdev.md": f"{a} dev-{_V} {b} in tests.\n",
        # findings: a statement of an edge nothing carries, a denial of a
        # direct edge, a denial of a CHAIN, a statement that is only a chain
        "bad.md": f"{a} {_V} {d} today.\n",
        "badneg.md": f"{a} does not {_V} {b} today.\n",
        "transneg.md": f"{a} does not {_V} {c} today.\n",
        "transpos.md": f"{a} {_V} {c} today.\n",
        # the two spans that read as confident findings before being read
        "pronoun.md": f"{a} is a sibling. It {_V} {c} today.\n",
        "relative.md": f"{a}, which the tool must not {_V} {b} here.\n",
        # a name the graph does not carry
        "foreign.md": f"{a} {_V} {_T}nosuch{_T} today.\n",
        # arrows: one the graph resolves, one it does not, one between names
        # the graph does not carry at all (a data-flow arrow, ignored)
        "chain.md": f"{a} {_A} {b} is the build path.\n",
        "chainbad.md": f"{a} {_A} {d} is the build path.\n",
        "flow.md": f"{_T}send_one{_T} {_A} {_T}recv_one{_T} is the hop.\n",
    }


def selftest() -> int:
    """Both polarities, both arms, and every discriminator that was added late.

    The fixture lives in a TEMPORARY directory rather than in this file: the
    production scan reads every tracked file, so a false claim spelled here
    would red the gate on its own explanation -- item 530's lesson about phrase
    lists, met from the other side.
    """
    names = {"alpha", "beta", "gamma", "delta"}
    edges = {("alpha", "beta"), ("beta", "gamma")}
    expected_findings = {
        "bad.md",
        "badneg.md",
        "transneg.md",
        "transpos.md",
        "chainbad.md",
    }
    expected_unresolved = {
        ("clause", "pronoun.md", "alpha->gamma"),
        ("clause", "relative.md", "alpha->beta"),
        ("clause", "foreign.md", "alpha->nosuch"),
    }
    with tempfile.TemporaryDirectory() as tmp:
        home = pathlib.Path(tmp)
        fixture = _fixture()
        for rel, body in fixture.items():
            (home / rel).write_text(body, encoding="utf-8")
        counts, findings, unresolved = scan(
            home, sorted(fixture), names, edges
        )

    if counts != {"clause+": 4, "clause-": 3, "arrow": 2}:
        print(
            f"prose-dep-graph: SELFTEST FAIL -- the fixture offers four "
            f"stated claims, three denials and two crate arrows, and the scan "
            f"counted {counts}. A data-flow arrow between two names the graph "
            f"does not carry must not be counted."
        )
        return 1
    chain_denial = [f for f in findings if f.startswith("transneg.md")]
    if len(chain_denial) != 1 or "through a chain" not in chain_denial[0]:
        print(
            f"prose-dep-graph: SELFTEST FAIL -- a denial of a dependency the "
            f"graph reaches through a CHAIN must be a finding and must say so; "
            f"a direct-edge check would swallow it, which is the sentence item "
            f"530 was opened for. Got {chain_denial}"
        )
        return 1
    if unresolved != expected_unresolved:
        print(
            f"prose-dep-graph: SELFTEST FAIL -- a pronoun subject, a relative "
            f"clause and a foreign name must all land unresolvable; the scan "
            f"said {sorted(unresolved)}"
        )
        return 1
    hit = {f.split(":")[0] for f in findings}
    # every unresolvable site is also a finding here, since the fixture
    # declares none of them
    if hit != expected_findings | {p for _, p, _ in expected_unresolved}:
        print(
            f"prose-dep-graph: SELFTEST FAIL -- expected findings on "
            f"{sorted(expected_findings)} plus the undeclared unresolvable "
            f"sites, and got {sorted(hit)}"
        )
        return 1
    print(
        "prose-dep-graph: selftest OK -- catches a stated edge nothing "
        "carries, a statement that is only a chain, a denial of a direct edge "
        "AND a denial of a CHAIN, spares both true polarities, refuses a "
        "pronoun subject, a relative clause and a foreign name, and leaves a "
        "data-flow arrow alone"
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in {"--check", "--selftest"}:
        print("usage: prose_dep_graph_gate.py --check | --selftest")
        return 2
    return selftest() if argv[0] == "--selftest" else check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
