#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2196 (no register item) — WHAT A CRATE'S OWN FILE SAYS ITS BUILD PULLS,
HELD TO THE CLOSURE `cargo metadata` RESOLVES.

## Why the citation says no item while the file answers for one

The debt this answers, 530, lives in the register half that is NOT the store,
so there is no `debt-` id to cite and the provenance convention's explicit
escape hatch is the honest form. 530 is item "the tree's prose contradicts a
derived fact, and nothing measures the class".

## What R2192 left, and why its own closing note was wrong about it

R2192 built `prose_dep_graph_gate.py` and closed 530 on the strength of it.
That gate adjudicates a dependency written as TWO NAMED CRATES in one sentence
-- "`a` depends on `b`" and "`a` -> `b`". Its closing note then declared the
FIRST measured case out of population, on the reasoning that a sentence naming
a NATIVE library rather than a crate is 526's subject and that
`apt_package_census.py`'s shortfall arm derives it.

Re-measured here, that is false in the direction that matters. 526 answers
"which packages must be installed on a runner"; nothing adjudicates a sentence
in which a crate says what ITS OWN BUILD pulls. And the sentence R2105 measured
was still in the tree, in two sites it never reached:

    crates/wz-codecs/src/lib.rs   "so this crate has no build script and
                                   pulls no libxml2/SCE toolchain"
    crates/wz-codecs/Cargo.toml   "so this crate no longer pulls `sce-build`
                                   (hence libxml2) into the build graph"

Both are FALSE. `cargo metadata --all-features` reaches `sce-build` from
`wz-codecs` through `sce-forge-runtime`'s build dependency, and `libxml` one
hop further. R2105 corrected `run-ci.sh` and `xtask/src/main.rs` and left the
two sites that make the claim about the crate the chain actually runs through.

## The form, and why it needs no marker

The winning shape twice over (R2190 for feature names, R2192 for crate pairs)
is: find the form the prose ALREADY writes, and adjudicate that. Here the form
is a crate's own file saying "this crate ..." -- and the subject of such a
sentence is not written down at all. It is the FILE'S LOCATION.

That is what makes this gate exact where a phrase list or a proximity window
would not be. The tree contains the same object word, the same verb and the
same polarity in two files with OPPOSITE truth values:

    crates/wz-codecs/src/lib.rs    "pulls no libxml2/SCE toolchain"       FALSE
    crates/wz-link-lwip/build.rs   "pulls no codegen toolchain (libxml2)"  TRUE

A banned-phrase grep reds both. A proximity read is right by luck. Only
resolving the subject from the owning package separates them, and this gate is
built on that.

## Two arms, two relations

* THE BUILD-SCRIPT ARM is exact and needs no name at all: "this crate has no
  build script" is answered by whether the owning package has a `custom-build`
  target. No vocabulary, no normalisation, no bridge.

* THE PULL ARM is held to the BUILD CLOSURE -- every package reachable over
  normal and build edges. A denial is only true if NOTHING carries it, and the
  sentence this item was opened for is carried by a build-script chain two hops
  down. Adjudicating a denial against direct edges would pass it, which is the
  same asymmetry R2192 recorded and the reason its fixture carries a chain.

  A POSITIVE pull claim is held to the same closure, and the difference from
  R2192 is deliberate: "pulls" is a closure verb -- it says what the build
  brings in, not what the manifest declares -- while "depends on" names the
  manifest's own edge. The tree currently writes no positive claim of this
  shape, so the arm carries no floor; the branch is exercised by the fixture
  instead, which is what keeps it from being dead code rather than a count
  that cannot fail.

## The object vocabulary is DERIVED, and ambiguity is refused

A "toolchain" is something that RUNS at build time, and what makes a package
run at build time is a build script. So the vocabulary is every package in the
graph carrying a `custom-build` target, plus every `links` value -- read off
`cargo metadata`, never typed.

Prose and cargo spell such a name differently (`libxml2` in prose, `libxml` in
the index), so both sides go through ONE declared normalisation: casefold,
drop non-alphanumerics, drop a trailing digit run, drop a trailing `sys`. It
is applied symmetrically, and when it collapses two distinct packages onto one
key the site is UNRESOLVED rather than adjudicated against a guess.

## Unclassified is not a pass

A denial whose object looks like a crate name -- lowercase with a hyphen --
but resolves to nothing is a claim this gate can see and cannot answer. It is
held in `UNRESOLVED_DECLARED` with a reason, and BOTH directions fail: an
undeclared site fails so the population cannot grow in silence, and a
declaration whose site no longer occurs fails so the list cannot become a
permission slip nobody re-reads.

Files owned by no workspace member are out of population, and that is a
statement rather than a silence: `vendor/` is foreign code, and a sentence
there is its author's claim about its own tree, not this one's.
"""

from __future__ import annotations

import collections
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"

# A leading comment marker, so a run of comment lines folds into the one
# paragraph the sentence was written as -- the measured claim spans two.
MARKER = re.compile(r"^[ \t]*(?://!|///|//|#|\*/|\*|--)[ \t]?")

# The subject, as this tree writes it. It names no crate: the crate is the one
# whose directory the file is in, which is what `owner_of` resolves.
SELF = re.compile(r"\b(?:this|the)\s+(?:crate|package)\b", re.I)

# A verb that says what a BUILD brings in. `depends on` is deliberately absent:
# that spelling names a manifest edge and is `prose_dep_graph_gate.py`'s arm.
PULL = re.compile(r"\b(?:pulls?|needs?|requires?|brings?\s+in)\b", re.I)

# The build-script arm's verb and its noun.
OWNS = re.compile(r"\b(?:has|have|carries|carry|ships?|declares?|contains?)\b", re.I)
BUILD_SCRIPT = re.compile(r"\bbuild[\s-]script\b", re.I)

# A span that stops this gate fixing the claim. Same reasoning as R2192: a full
# stop or a relative pronoun ends the clause the subject belonged to.
BREAKS = re.compile(r"[.;:—]|\b(?:which|that|whose|who)\b", re.IGNORECASE)

NEGATION = re.compile(r"\b(?:no|not|never|cannot|without)\b", re.I)

# A token shaped like a crate or tool name. Used ONLY to decide that an
# unresolvable object is a claim this gate can see -- never to resolve one.
CRATEISH = re.compile(r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+)+\b")

TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")

# A span in quotation marks is REPORTED SPEECH, not a claim this file makes.
#
# This is the R2161 counterexample, met head-on: a round that CORRECTS a false
# sentence has to be able to quote it, and a gate that reds the correction is
# a phrase list wearing a derivation's clothes -- the exact failure item 530
# rejects. The tree already writes retractions this way and has twice: R2105's
# in `run-ci.sh` and in `xtask/src/main.rs` both read `that clause used to end
# "..."`. So the convention is the tree's own, not one this gate invents.
#
# The residue, stated rather than hidden: a false claim someone puts inside
# quotation marks passes. That is the price of being able to retract one at
# all, and it is bounded -- quoting a sentence is not how a crate documents
# itself, and the two arms still adjudicate every unquoted claim in the same
# file. Backticks are NOT reported speech: they mark a name.
QUOTED = re.compile(r"\"[^\"\n]*\"|“[^”\n]*”")

# How far past the subject the verb may sit, and past the verb the object.
SUBJECT_SPAN = 140
OBJECT_SPAN = 70
# A negation binds the verb from just before it ("no longer pulls") or from
# between it and the object ("pulls no libxml2"). A negation further back in
# the span belongs to some other clause -- in the measured sentence it belongs
# to the build-script half -- so reading the whole span would be right there by
# accident and wrong elsewhere.
PREVERB_NEGATION_SPAN = 25
POSTVERB_NEGATION_SPAN = 30

# (arm, path, "<package>:<object>") -> why this gate cannot adjudicate it.
#
# BOTH DIRECTIONS, as in `prose_dep_graph_gate.py`: an undeclared unresolvable
# site FAILS and a declared entry that no longer occurs FAILS.
UNRESOLVED_DECLARED: dict[tuple[str, str, str], str] = {
    (
        "pull",
        "crates/wz-ap-demo-app/Cargo.toml",
        "wz-ap-demo-app:sce-codegen",
    ): (
        "`sce-codegen` is the codegen BINARY, not a package any cargo graph "
        "carries, so the resolve graph has no answer for it; the half of the "
        "same sentence a graph CAN answer -- that the crate has no build "
        "script -- is adjudicated by this gate's other arm"
    ),
    (
        "pull",
        "crates/wz-runtime-coop/Cargo.toml",
        "wz-runtime-coop:sce-codegen",
    ): (
        "the same claim about the codegen BINARY, which no cargo graph carries"
    ),
    (
        "pull",
        "crates/wz-runtime-tokio/Cargo.toml",
        "wz-runtime-tokio:sce-codegen",
    ): (
        "the same claim about the codegen BINARY, which no cargo graph carries"
    ),
    (
        "pull",
        "crates/wz-session-core/Cargo.toml",
        "wz-session-core:sce-codegen",
    ): (
        "the same claim about the codegen BINARY, which no cargo graph carries"
    ),
    (
        "pull",
        "crates/wz-switchboard-example/Cargo.toml",
        "wz-switchboard-example:sce-codegen",
    ): (
        "the same claim about the codegen BINARY, which no cargo graph carries"
    ),
}


def normalise(name: str) -> str:
    """The ONE bridge between a prose spelling and an index spelling.

    Applied to both sides. `libxml2` and `libxml` meet here, and so do
    `lwip-sys` and the `links = "lwip"` it declares.
    """
    flat = re.sub(r"[^a-z0-9]", "", name.lower())
    flat = re.sub(r"\d+$", "", flat)
    return re.sub(r"sys$", "", flat)


def metadata() -> dict:
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features"],
        cwd=CRATES,
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(f"cargo metadata failed: {out.stderr[:400]}")
    return json.loads(out.stdout)


def build_edges(meta: dict) -> set[tuple[str, str]]:
    """The DIRECT normal and build edges each manifest declares.

    Direct edges rather than a pre-computed closure, so the walk below is the
    thing under test: a fixture can then put a package two hops away and a
    denial adjudicated against direct edges fails the selftest instead of
    passing the sentence item 530 was opened for.

    Dev edges are out: a dev-dependency is not in what a consumer's build
    pulls, and the claims this reads are about a consumer's build.
    """
    return {
        (pkg["name"], dep["name"])
        for pkg in meta["packages"]
        for dep in pkg["dependencies"]
        if dep["kind"] in (None, "build")
    }


def reachable(edges: set[tuple[str, str]], start: str) -> set[str]:
    """Every package `start` brings into a build, at any depth."""
    out: dict[str, set[str]] = collections.defaultdict(set)
    for src, dst in edges:
        out[src].add(dst)
    seen: set[str] = set()
    stack = [start]
    while stack:
        for nxt in out.get(stack.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def build_time_vocabulary(meta: dict) -> dict[str, set[str]]:
    """Normalised name -> the packages that spell it.

    A package RUNS at build time when it has a build script, and a `links`
    value is the native library one of those brings in. Both are read off the
    metadata; neither is typed here.
    """
    vocab: dict[str, set[str]] = collections.defaultdict(set)
    for pkg in meta["packages"]:
        if any(t["kind"] == ["custom-build"] for t in pkg["targets"]):
            vocab[normalise(pkg["name"])].add(pkg["name"])
        if pkg.get("links"):
            vocab[normalise(pkg["links"])].add(pkg["name"])
    return vocab


def has_build_script(meta: dict) -> set[str]:
    return {
        p["name"]
        for p in meta["packages"]
        if any(t["kind"] == ["custom-build"] for t in p["targets"])
    }


def owners(meta: dict) -> list[tuple[str, str]]:
    """(directory, package) for every workspace member, longest path first."""
    members = set(meta["workspace_members"])
    out = [
        (str(pathlib.Path(p["manifest_path"]).parent), p["name"])
        for p in meta["packages"]
        if p["id"] in members
    ]
    return sorted(out, key=lambda e: -len(e[0]))


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


def resolve_object(
    tail: str, vocab: dict[str, set[str]]
) -> tuple[str | None, str | None, str | None]:
    """(token, package, why-unresolvable) for the first object token that bites.

    The first token whose normalisation is a key wins. A key several packages
    share resolves to none of them: guessing is how a gate reports on the wrong
    subject, and this axis has already paid for one of those.
    """
    for token in TOKEN.findall(tail):
        key = normalise(token)
        if not key or key not in vocab:
            continue
        candidates = vocab[key]
        if len(candidates) > 1:
            return token, None, (
                f"`{token}` normalises onto {len(candidates)} build-time "
                f"packages ({', '.join(sorted(candidates))}), and adjudicating "
                f"against a guess is how a gate reports on the wrong subject"
            )
        return token, sorted(candidates)[0], None
    return None, None, None


def scan(
    root: pathlib.Path,
    files: list[str],
    owner_of,
    edges: set[tuple[str, str]],
    scripted: set[str],
    vocab: dict[str, set[str]],
) -> tuple[dict[str, int], list[str], set[tuple[str, str, str]]]:
    """(per-arm adjudicated counts, findings, unresolvable site keys)."""
    counts = {"build-script": 0, "pull-": 0, "pull+": 0}
    findings: list[str] = []
    unresolved: set[tuple[str, str, str]] = set()

    for rel in sorted(files):
        path = root / rel
        # The frozen ledger is prose ABOUT this tree, not a claim BY a crate.
        if rel.startswith("docs/.atomic/") or not path.is_file():
            continue
        package = owner_of(rel)
        if package is None:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for raw, line in paragraphs(text):
            # Offsets are preserved so a finding still points at the right
            # line; only the reported speech stops being readable as a claim.
            para = QUOTED.sub(lambda m: " " * len(m.group(0)), raw)
            for subject in SELF.finditer(para):
                rest = para[subject.end() : subject.end() + SUBJECT_SPAN]

                owns = OWNS.search(rest)
                if owns and not BREAKS.search(rest[: owns.start()]):
                    after = rest[owns.end() : owns.end() + OBJECT_SPAN]
                    script = BUILD_SCRIPT.search(after)
                    if script and not BREAKS.search(after[: script.start()]):
                        counts["build-script"] += 1
                        denied = bool(NEGATION.search(after[: script.start()]))
                        actual = package in scripted
                        if denied and actual:
                            findings.append(
                                f"{rel}:{line}: prose says `{package}` has no "
                                f"build script and its manifest declares a "
                                f"`custom-build` target. The claim is about "
                                f"the crate this file belongs to, and cargo "
                                f"answers it exactly."
                            )
                        elif not denied and not actual:
                            findings.append(
                                f"{rel}:{line}: prose says `{package}` has a "
                                f"build script and its manifest declares no "
                                f"`custom-build` target."
                            )

                pull = PULL.search(rest)
                if pull is None or BREAKS.search(rest[: pull.start()]):
                    continue
                tail = rest[pull.end() : pull.end() + OBJECT_SPAN]
                token, obj, why = resolve_object(tail, vocab)
                denied = bool(
                    NEGATION.search(tail[:POSTVERB_NEGATION_SPAN])
                ) or bool(
                    NEGATION.search(rest[: pull.start()][-PREVERB_NEGATION_SPAN:])
                )
                if obj is None:
                    # Only a claim this gate can SEE is one it must answer for:
                    # a denial naming something shaped like a crate.
                    if not denied or not CRATEISH.search(tail):
                        continue
                    named = token or CRATEISH.search(tail).group(0)
                    key = ("pull", rel, f"{package}:{named}")
                    unresolved.add(key)
                    if key not in UNRESOLVED_DECLARED:
                        findings.append(
                            f"{rel}:{line}: `{package}` denies pulling "
                            f"`{named}` and this gate cannot adjudicate it -- "
                            + (
                                why
                                or "no package in the resolve graph spells that "
                                "name, so there is nothing to reach"
                            )
                            + ". Unclassified is not a pass: rewrite the "
                            f"sentence to name a package the graph carries, or "
                            f"declare the site in `UNRESOLVED_DECLARED` with "
                            f"the reason."
                        )
                    continue
                reached = obj in reachable(edges, package)
                if denied:
                    counts["pull-"] += 1
                    if reached:
                        findings.append(
                            f"{rel}:{line}: prose says `{package}` pulls no "
                            f"`{obj}` (written `{token}`), and `cargo metadata "
                            f"--all-features` reaches it over normal and build "
                            f"edges. Item 530's first measured case is a "
                            f"DENIAL a build-script chain carries, and this is "
                            f"the crate that chain runs through."
                        )
                else:
                    counts["pull+"] += 1
                    if not reached:
                        findings.append(
                            f"{rel}:{line}: prose says `{package}` pulls "
                            f"`{obj}` (written `{token}`), and `cargo metadata "
                            f"--all-features` does not reach it over normal or "
                            f"build edges at all."
                        )
    return counts, findings, unresolved


def owner_resolver(table: list[tuple[str, str]], root: pathlib.Path):
    def owner_of(rel: str) -> str | None:
        full = str(root / rel)
        for directory, package in table:
            if full.startswith(directory + "/"):
                return package
        return None

    return owner_of


def check() -> int:
    meta = metadata()
    edges = build_edges(meta)
    scripted = has_build_script(meta)
    vocab = build_time_vocabulary(meta)
    table = owners(meta)
    counts, findings, unresolved = scan(
        ROOT, tracked_files(), owner_resolver(table, ROOT), edges, scripted, vocab
    )

    # PER-ARM floors. A total cannot say WHICH arm went to zero, and the arm
    # this gate was built for is the denial one.
    for arm, label in (
        ("build-script", "build-script claim"),
        ("pull-", "denied build-closure claim"),
    ):
        if counts[arm] == 0:
            print(
                f"prose-build-closure: FAIL -- no {label} was adjudicated. A "
                f"population of zero reports green whatever the tree says, so "
                f"this arm cannot be allowed to go quiet on its own. Both "
                f"arms had a subject when this was written. Two things bring "
                f"it to zero and they need opposite answers: the derivation "
                f"stopped matching a form the tree still writes (fix the "
                f"derivation), or the tree genuinely stopped writing that "
                f"claim (retire the arm deliberately, in a commit that says "
                f"so). Neither is a green run."
            )
            return 1

    stale = sorted(set(UNRESOLVED_DECLARED) - unresolved)
    for arm, rel, pair in stale:
        findings.append(
            f"{rel}: `UNRESOLVED_DECLARED` holds the {arm} site `{pair}`, and "
            f"the scan no longer finds it. A declaration that outlives its "
            f"site is a permission slip nobody re-reads -- delete the row."
        )

    if findings:
        print(f"prose-build-closure: FAIL -- {len(findings)} finding(s)")
        for line in findings:
            print(f"  {line}")
        return 1
    print(
        f"prose-build-closure: {counts['build-script']} build-script claim(s), "
        f"{counts['pull-']} denied and {counts['pull+']} stated build-closure "
        f"claim(s) all agree with `cargo metadata --all-features`, "
        f"{len(UNRESOLVED_DECLARED)} site(s) declared unresolvable and all "
        f"still present"
    )
    return 0


def _fixture() -> dict[str, str]:
    """Shapes this scanner has to separate, plus their controls.

    The graph behind it is `alpha` -> `beta` -> `libtool`, and `alpha` has NO
    direct edge to `libtool`. That second hop is not decoration: a denial
    adjudicated against direct edges swallows a chain, which is precisely the
    sentence item 530 was opened for and precisely how a build-script chain
    carried it. `alpha` carries a build script; `beta` does not.

    The prose spells the tool `libtool2` and the index spells it `libtool`, so
    the fixture also exercises the one normalisation this gate declares.
    """
    return {
        # controls, one per branch that must stay silent
        "alpha/ok_script.rs": "// this crate has a build script today.\n",
        "beta/ok_noscript.rs": "// this crate has no build script today.\n",
        "beta/ok_denial.rs": "// this crate pulls no libgone2 at all.\n",
        "beta/ok_stated.rs": "// this crate pulls libtool2 for codegen.\n",
        "alpha/ok_break.rs": "// this crate is small. Nothing pulls libtool2.\n",
        # the R2161 counterexample: a round correcting the false sentence has
        # to be able to QUOTE it, and the quoted form must not be a finding
        "alpha/ok_quoted.rs": (
            '// It used to end "this crate pulls no libtool2", and that was'
            " FALSE.\n"
        ),
        # findings
        "alpha/bad_script.rs": "// this crate has no build script today.\n",
        "beta/bad_script.rs": "// this crate has a build script today.\n",
        "alpha/bad_chain.rs": "// this crate pulls no libtool2 at all.\n",
        "beta/bad_longer.rs": "// this crate no longer pulls libtool2 here.\n",
        "beta/bad_stated.rs": "// this crate pulls libgone2 for codegen.\n",
        "beta/bad_unknown.rs": "// this crate pulls no sce-codegen here.\n",
        # out of population: no workspace member owns it
        "outside/quiet.rs": "// this crate pulls no libtool2 at all.\n",
    }


def selftest() -> int:
    """Both arms, both polarities, and the discriminators added late.

    The fixture lives in a TEMPORARY directory rather than in this file: the
    production scan reads every tracked file, so a false claim spelled here
    would red the gate on its own explanation.
    """
    edges = {("alpha", "beta"), ("beta", "libtool")}
    scripted = {"alpha", "libtool"}
    vocab = {
        normalise("libtool"): {"libtool"},
        normalise("libgone"): {"libgone"},
    }
    expected_findings = {
        "alpha/bad_script.rs",
        "beta/bad_script.rs",
        "alpha/bad_chain.rs",
        "beta/bad_longer.rs",
        "beta/bad_stated.rs",
        "beta/bad_unknown.rs",
    }
    expected_unresolved = {("pull", "beta/bad_unknown.rs", "beta:sce-codegen")}

    with tempfile.TemporaryDirectory() as tmp:
        home = pathlib.Path(tmp)
        fixture = _fixture()
        for rel, body in fixture.items():
            (home / rel).parent.mkdir(parents=True, exist_ok=True)
            (home / rel).write_text(body, encoding="utf-8")
        table = [(str(home / "alpha"), "alpha"), (str(home / "beta"), "beta")]
        counts, findings, unresolved = scan(
            home,
            sorted(fixture),
            owner_resolver(sorted(table, key=lambda e: -len(e[0])), home),
            edges,
            scripted,
            vocab,
        )

    if counts != {"build-script": 4, "pull-": 3, "pull+": 2}:
        print(
            f"prose-build-closure: SELFTEST FAIL -- the fixture offers four "
            f"build-script claims, three denials and two stated pulls, and the "
            f"scan counted {counts}. A sentence owned by no workspace member, "
            f"one broken by a full stop, and one QUOTED so a round can retract "
            f"it must none of them be counted."
        )
        return 1
    if any(f.startswith("alpha/ok_quoted.rs") for f in findings):
        print(
            "prose-build-closure: SELFTEST FAIL -- a false claim QUOTED in "
            "order to be retracted must not be a finding. R2161 is the "
            "counterexample: a round that renames a thing has to be able to "
            "write down what it used to be called, and a gate that reds its "
            "own correction is the phrase list item 530 rejects."
        )
        return 1
    chain = [f for f in findings if f.startswith("alpha/bad_chain.rs")]
    if len(chain) != 1 or "build-script chain carries" not in chain[0]:
        print(
            f"prose-build-closure: SELFTEST FAIL -- a denial of a package the "
            f"build closure reaches through a CHAIN must be a finding; a "
            f"direct-edge check would swallow it, which is the sentence item "
            f"530 was opened for. Got {chain}"
        )
        return 1
    if unresolved != expected_unresolved:
        print(
            f"prose-build-closure: SELFTEST FAIL -- a denial naming something "
            f"no package spells must land unresolvable; the scan said "
            f"{sorted(unresolved)}"
        )
        return 1
    hit = {f.split(":")[0] for f in findings}
    if hit != expected_findings:
        print(
            f"prose-build-closure: SELFTEST FAIL -- expected findings on "
            f"{sorted(expected_findings)} and got {sorted(hit)}"
        )
        return 1
    print(
        "prose-build-closure: selftest OK -- catches a build script a crate "
        "denies and one it claims without having, a denial of a package the "
        "closure reaches through a CHAIN, a `no longer` denial, a stated pull "
        "of a package nothing reaches and a denial naming no package at all; "
        "spares both true polarities, a clause a full stop breaks, a false "
        "claim QUOTED so a round can retract it, and a file no workspace "
        "member owns"
    )
    return 0


def main(argv: list[str]) -> int:
    """A required mode with no default. Read and write are not opposites here,
    but `--check` and a future `--apply` would be, and R2104b paid for a script
    that decided its mode by what was NOT in `sys.argv`."""
    if argv == ["--check"]:
        return check()
    if argv == ["--selftest"]:
        return selftest()
    print("usage: prose_build_closure_gate.py --check | --selftest")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
