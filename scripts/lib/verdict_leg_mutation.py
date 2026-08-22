#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y726 (N14) — MUTATE EACH LEG OF THE VERDICT AND REQUIRE A TEST TO REDDEN.

WHAT THIS IS. The sufficient condition `verdict_reason_lint` cannot express.
That gate asks whether a test NAMES each `VerdictReason`; this one asks whether
any test DEPENDS on it. For each variant in turn the leg is broken, the suite is
run, and at least one test must fail. A leg no test misses is a leg that can be
deleted in silence.

TWO OPERATORS, BECAUSE A LEG HAS TWO WAYS TO BE WRONG (R311y727, N16).

  * `sever` — the `out.push(...)` becomes a statement with no effect, so no
    capture can raise the leg. This asks: does anything notice when the reason
    STOPS being reported?
  * `widen` — the single-line `if` guarding that push is `|| true`, so every
    capture raises the leg. This asks: does anything notice when the reason
    starts being reported by captures that are FINE?

R311y726 shipped only the first and wrote the gap down: a guard that is too wide
-- `>= 0` where `> 0` was meant, or a counter read off the wrong plane -- keeps
its push, keeps raising the reason on the fixtures that trip it, and walks
through a severing sweep untouched. The defect it hides is the worse-reading
one: a verdict that cries incomplete over a whole capture teaches an operator to
stop reading verdicts. `widen` is the smallest operator that reaches it, and it
is the exact complement of `sever` -- the two pin the guard from both sides,
false-negative and false-positive.

The condition is preserved inside the widened guard (`(COND) || true`, never a
bare `true`) so that every binding it reads stays read. A bare `true` orphans
the `let`s above it, and this tool would then be reporting its own dead-code
warnings as facts about the verdict.

WHY IT HAD TO EXIST. R311y715 ran exactly this sweep BY HAND and found nine of
the twenty-four guards in the old `is_complete` binding nothing. R311y725 built
the static gate and MEASURED thirteen of twenty-three variants named by no test
at all -- then bound all thirteen, most of them by turning an existing
`!is_complete()` witness into an assertion on `reasons()`. Neither round proved
the legs are load-bearing; both proved something weaker. The register carried the
gap as N14, and a hand-run sweep is not a gate.

WHAT A RESULT MEANS.

  * a mutant whose tests FAIL -- the leg is load-bearing. This is the pass.
  * a mutant whose tests PASS -- nothing in the suite depends on that half of
    the leg. Severed, it can be deleted and no one will know; widened, it can
    fire on every capture in the tree and no one will know.
  * a mutant that does not COMPILE -- proves NOTHING, and is reported as a
    failure of this tool rather than a finding about the code. A mutation that
    cannot be expressed needs a human, and counting it as "red, therefore
    load-bearing" is exactly the false pass this gate exists to refuse.
  * a leg whose guard this tool cannot SEE is likewise a failure of the tool
    and is named. Skipping it would answer half the question in silence, which
    is the population-of-zero green this file exists to refuse.

WHY IT MUTATES THE TREE IN PLACE. The alternative is a copy, and the copy is
worse than it looks: this workspace's cargo root is `crates/` with path
dependencies reaching `../vendor/`, so a hermetic copy is most of the repository.
Instead the original bytes are held, every exit path restores them, and the
restore is verified BYTE FOR BYTE before this reports anything. A backup left
behind is a previous run that died, and the next run REFUSES rather than guessing
which of the two files on disk is the real one.

THE BASELINE IS CHECKED FIRST, and that is not a formality: over a red tree every
mutant is red and this gate would report every leg load-bearing while measuring
nothing. A population-of-zero green, arriving through the front door.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LINT = Path(__file__).resolve().parent / "verdict_reason_lint.py"

# The file the legs live in, and where its untouched bytes are held while a
# mutant is on disk.
SOURCE = Path("crates/wz-capture/src/report.rs")
BACKUP = Path("crates/target/verdict-mutation/report.rs.pristine")

# A build directory of this sweep's own, so twenty-three recompiles do not
# evict the tree's ordinary one.
TARGET_DIR = Path("crates/target/verdict-mutation/target")

# One leg, as `reasons()` raises it.
PUSH = re.compile(r"^(\s*)out\.push\(VerdictReason::(\w+)\);\s*$", re.M)

# One leg's GUARD -- the single-line `if` whose whole body is that push.
#
# The shape is insisted upon rather than searched for. A guard spread over
# several lines, or one holding more than the push, is not matched here and is
# then reported BY NAME as a leg this tool could not ask its second question of.
# Guessing at where such a condition begins is how a mutation tool starts
# producing findings about its own parsing.
GUARD = re.compile(
    r"^(?P<indent>[ \t]*)if (?P<cond>.+) \{\n"
    r"(?P<push>[ \t]*out\.push\(VerdictReason::(?P<variant>\w+)\);)$",
    re.M,
)


def sever(pristine: str, variant: str) -> str:
    """Operator 1 — this leg can no longer be raised by any capture."""
    return PUSH.sub(
        lambda m: (
            f"{m.group(1)}let _ = VerdictReason::{m.group(2)};"
            if m.group(2) == variant
            else m.group(0)
        ),
        pristine,
    )


def widen(pristine: str, variant: str) -> str:
    """Operator 2 — this leg is now raised by EVERY capture.

    `(COND) || true` and not `true`: the condition still runs, so every binding
    it reads stays read and the mutant does not collect unused-variable
    warnings that have nothing to do with the verdict.
    """

    def rewrite(m: re.Match) -> str:
        if m.group("variant") != variant:
            return m.group(0)
        return f"{m.group('indent')}if ({m.group('cond')}) || true {{\n{m.group('push')}"

    return GUARD.sub(rewrite, pristine)


# A comparison against a literal, which is what almost every guard here is.
LITERAL_CMP = re.compile(r">\s*(\d+)\b")


def tighten(cond: str) -> str | None:
    """`cond` with its threshold moved ONE step, or None if it has no threshold.

    Two shapes, in order:

      * `.. > <literal> ..` becomes `.. > <literal + 1> ..`, which reaches the
        comparisons written inside a closure (`is_some_and(|q| q.x > 0)`) as
        well as the plain ones.
      * a single TOP-LEVEL `>` between two expressions becomes
        `lhs > (rhs) + 1`. Depth-aware, so a `>` inside a call's arguments is
        not mistaken for the comparison.

    Ambiguity returns None rather than guessing: two literal comparisons in one
    guard could be tightened two ways and picking one silently would make this
    operator's question unstatable.
    """
    hits = list(LITERAL_CMP.finditer(cond))
    if len(hits) == 1:
        m = hits[0]
        return f"{cond[: m.start()]}> {int(m.group(1)) + 1}{cond[m.end() :]}"
    if len(hits) > 1:
        return None
    depth, at, seen = 0, -1, 0
    for i, ch in enumerate(cond):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == ">" and depth == 0:
            if i + 1 < len(cond) and cond[i + 1] == "=":
                continue
            if i and cond[i - 1] in "-=<>":
                continue
            at, seen = i, seen + 1
    if seen == 1:
        return f"{cond[:at]}> ({cond[at + 1 :].strip()}) + 1"
    return None


def boundary(pristine: str, variant: str) -> str | None:
    """Operator 3 — the leg's threshold moves ONE step.

    R311y727 (N18) — `sever` and `widen` are the two EXTREMES of a guard: never
    true and always true. A guard wrong by a step sits between them, and both
    extremes step right over it. `> 1` where `> 0` was meant keeps firing on
    every fixture that trips the leg hard and stays quiet exactly where the
    right guard was quiet -- the one capture it now misses is the one holding a
    single instance of the thing.

    So this asks a question the other two cannot: is there a fixture that trips
    this leg with the SMALLEST possible evidence? A suite whose every fixture
    loses three packets never notices a reader that stopped reporting one.

    Returns None when the guard holds no threshold to move -- `drops().any()`,
    `!gaps().is_clean()`. That is a fact about the guard, not a failure, and it
    is reported by name rather than skipped.
    """
    reached = False

    def rewrite(m: re.Match) -> str:
        nonlocal reached
        if m.group("variant") != variant:
            return m.group(0)
        tightened = tighten(m.group("cond"))
        if tightened is None:
            return m.group(0)
        reached = True
        return f"{m.group('indent')}if {tightened} {{\n{m.group('push')}"

    out = GUARD.sub(rewrite, pristine)
    return out if reached else None


# ─── The PREDICATE layer (R311y729, N20) ────────────────────────────
#
# Eight of the twenty-three guards hold no threshold of their own: they ask
# `drops().any()`, `!gaps().is_clean()`, `!selection().is_decisive()`. R311y728
# named them and moved on, which was honest and left the most interesting legs
# -- the plane and bounds ones, whose fixtures are hardest to reduce to a single
# instance -- with no boundary question at all.
#
# The thresholds are one level down, inside those predicates, so this follows
# the call ONE STEP and moves them there. What that buys is the same question in
# a different unit: not "does a fixture trip THIS LEG with the smallest
# evidence" but "does any test depend on this PREDICATE's threshold". The unit
# is deliberately not the leg -- three legs share `is_decisive`, so a mutant
# there is answered by any of them, and claiming otherwise would be this tool
# reporting a precision it does not have.
#
# Each recipe is an exact (anchor, old, new) inside one function. A recipe whose
# `old` no longer matches, or matches twice, FAILS the run rather than being
# skipped: the predicate moved, and a stale recipe silently mutating nothing is
# the population-of-zero green in its purest form.

_IS_CLEAN_OLD = """    pub fn is_clean(&self) -> bool {
        *self == Self::default()
    }"""


def _relax_field(*fields: str) -> str:
    """`is_clean` that forgives ONE of each named field, and nothing else.

    R311y730 (N22) — several fields at once, because some COUNTERS ARE COUPLED.
    All three producers of `halted_batches` and `unparsed_bytes` raise them in
    one `if`, so a capture holding a single halt has both at one; relaxing
    either alone leaves the other holding the plane unclean and the mutant
    survives no matter what any fixture does. Asking about the PAIR is the
    question a fixture can answer, which is R311y716's lesson in the small: when
    legs are coupled, move the unit rather than demand an impossible isolation.
    """
    body = "\n".join(
        f"        relaxed.{f} = relaxed.{f}.saturating_sub(1);" for f in fields
    )
    return f"""    pub fn is_clean(&self) -> bool {{
        let mut relaxed = *self;
{body}
        relaxed == Self::default()
    }}"""


PREDICATES = [
    # `DissectionDrops::any` -- six counters ORed. Each is its own question:
    # "is there a capture that gave up exactly one of THESE".
    *[
        (
            f"drops.any/{f}",
            "crates/wz-capture/src/lib.rs",
            "pub fn any(&self) -> bool {",
            f"self.{f} > 0",
            f"self.{f} > 1",
        )
        for f in (
            "frames",
            "stream_bytes",
            "skipped",
            "flows",
            "scouting",
            "scout_askers",
        )
    ],
    # R311y860 -- `SkipCensus::bytes_absent`, six counters SUMMED. Same unit as
    # `drops.any` above and for the same reason: each field is a different way
    # for the capture to be short, and zeroing one asks "is there a capture that
    # loses bytes exactly THIS way, and does anything notice".
    #
    # The sum has no threshold inside it, which is why the relaxation is per
    # field rather than a `> 0` moved to `> 1`: the threshold lives at the
    # guard, where `boundary` already mutates it. What is one level down here is
    # the SET of reasons, not a number.
    *[
        (
            f"SkipCensus.bytes_absent/{f}",
            "crates/wz-capture/src/lib.rs",
            "pub fn bytes_absent(&self) -> usize {",
            f"self.{f}",
            "0",
        )
        for f in (
            "unsupported_link_type",
            "truncated",
            "ipv4_fragment",
            "ipv6_extension_chain",
            "ipv6_fragment",
            "unwalked_encapsulation",
            # R311y864 -- GRE opened, payload ethertype not walked. A seventh
            # way to be short, and it is here because `unswept_summands`
            # DEMANDED it: the sweep named `self.gre_payload` on the first run
            # after the field landed, which is the first time that check has
            # fired on a round that was not the one that wrote it.
            "gre_payload",
            # Round 2013 (item 256) -- a chain longer than the walk goes, split
            # out of `unwalked_encapsulation` so the page stops naming an
            # OPENED protocol as unsupported. An eighth way to be short, and it
            # is here for the same reason `gre_payload` is: the check demanded
            # it on the first run after the field landed. Item 256 predicted
            # this line ("a census field grows and so does a recipe") before
            # either was written.
            "encapsulation_too_deep",
        )
    ],
    # R311y861 -- `Dissection::unfinished_fragment_chains`, three ENDS summed.
    #
    # `ip_fragment_pending` left the list above because a piece held at the door
    # is not absent: the datagram it belongs to may complete a packet later, and
    # counting it as a loss made the verdict fire on ordinary fragmentation. The
    # question moved one level out, from pieces to CHAINS, and this is where it
    # is asked now.
    #
    # Registered per end rather than as one guard even though `uncovered_calls`
    # does not demand it -- the guard holds a single call, so the check that
    # forced the six recipes above never reaches this one. Declared anyway: the
    # three ends are three different fixtures and three different things for an
    # operator to do about them, and a sweep that only moved the sum would pass
    # with two of them witnessed by nothing.
    *[
        (
            f"Dissection.unfinished_fragment_chains/{expr}",
            "crates/wz-capture/src/lib.rs",
            "pub fn unfinished_fragment_chains(&self) -> usize {",
            expr,
            "0",
        )
        for expr in (
            "s.expired",
            "s.evicted",
            "self.open_fragment_chains()",
        )
    ],
    # The two gap structs compare against `default()`, so there is no threshold
    # to move -- the relaxation has to be per FIELD, which is the right unit
    # anyway: each field is a different way for the plane to be short.
    *[
        (
            f"ThroughputGaps.is_clean/{'+'.join(fs)}",
            "crates/wz-capture/src/agg.rs",
            _IS_CLEAN_OLD,
            _IS_CLEAN_OLD,
            _relax_field(*fs),
        )
        # The first is a PAIR because those two counters cannot move apart.
        for fs in (
            ("halted_batches", "unparsed_bytes"),
            ("undecompressible_batches",),
            ("unresolvable_fragments",),
        )
    ],
    *[
        (
            f"ExchangeGaps.is_clean/{f}",
            "crates/wz-capture/src/exchange.rs",
            _IS_CLEAN_OLD,
            _IS_CLEAN_OLD,
            _relax_field(f),
        )
        for f in (
            "orphan_responses",
            "unstamped",
            "non_monotonic",
            "unattributed_requests",
        )
    ],
    (
        "Selection.is_decisive/undecided",
        "crates/wz-capture/src/filter.rs",
        "pub fn is_decisive(&self) -> bool {",
        "self.undecided == 0",
        "self.undecided <= 1",
    ),
]


# Predicate thresholds NO fixture in this tree reaches at exactly one, each with
# why it is not paid yet. Registered rather than tolerated: every one is printed
# on the way to OK, so the list is read every run, and a survivor that is NOT on
# it still fails. R311y729 measured nine survivors and paid the three that could
# be reduced to a single instance today (the exchange gap counters); these six
# need a fixture built around the bound rather than a fixture adjusted.
#
# R311y860 admits a SECOND class, because the first two entries are not of the
# kind the paragraph above describes and filing them as "unbuilt" would be the
# dishonest half of an honest register. `SkipReason::Ipv4Fragment` and
# `SkipReason::Ipv6Fragment` are constructed NOWHERE in this tree: every IP
# fragment `Dissection` sees goes to the reassembly table and is recorded as
# `IpFragmentPending` or completes. The counters they feed are therefore
# structurally zero, and no fixture can move them without a code change.
#
# So the register now carries two sentences, and each entry says which it is:
# UNBUILT (a fixture nobody has written) or UNREACHABLE (a counter no path
# sets). The difference matters to a reader deciding what to do about it — the
# first is a test to write, the second is a decision about whether the counter
# should exist at all, which is filed as a carry rather than taken here.
UNWITNESSED = {
    "SkipCensus.bytes_absent/ipv4_fragment": (
        "UNREACHABLE: nothing in this tree constructs `SkipReason::Ipv4Fragment`. "
        "`Dissection::push_packet` routes every IPv4 fragment to `push_fragment`, "
        "which records `IpFragmentPending` or completes the datagram "
        "(crates/wz-capture/src/lib.rs:4125). The variant exists for a consumer "
        "of `link::strip_transport` that declines to reassemble, and this tree "
        "has none, so the counter is structurally zero and a fixture cannot "
        "move it."
    ),
    "SkipCensus.bytes_absent/ipv6_fragment": (
        "UNREACHABLE: the v6 twin of the row above, and unreachable for the same "
        "reason — the IPv6 fragment header reaches the same reassembly table. "
        "Both are reported in the skip census and in both renderings as fields "
        "that can never be non-zero, which is the part worth deciding about."
    ),
}


# Which (TYPE, predicate) pairs the recipes above cover.
#
# R311y731 (N23) made this check exist; R311y732 (N24) raises it from names to
# TYPES, which is what it needed to actually answer the question. Keying on the
# accessor name accepted `(gaps, is_clean)` for any struct reached through a
# method called `gaps` -- and this tree already has two: `ExchangeTable::gaps`
# returns `ExchangeGaps` while `PayloadCensus::gaps` and `ThroughputTable::gaps`
# return `ThroughputGaps`. A third type behind the same name would have walked
# straight through.
#
# The type is READ FROM THE DECLARATION rather than inferred: an accessor's
# return type is written down at its `fn`, and a recipe sits inside an `impl`
# block that names the type it mutates. Neither needs type inference, which is
# what made R311y731 stop at names.
COVERED_TYPES = {
    ("DissectionDrops", "any"),
    ("SkipCensus", "bytes_absent"),
    ("Dissection", "unfinished_fragment_chains"),
    ("ThroughputGaps", "is_clean"),
    ("ExchangeGaps", "is_clean"),
    ("Selection", "is_decisive"),
}

# A no-argument method call. Adapters (`is_some_and(..)`, `map_or(..)`) carry
# arguments and so never match -- their inner comparison is `boundary`'s job,
# not a predicate's.
CALL = re.compile(r"\.(\w+)\(\)")

# An accessor's declared return type, and the `impl` a recipe sits in.
#
# R311y860 — the return may be a REFERENCE, and until this round the pattern
# stopped at the `&`. `Dissection::skip_census` returns `&SkipCensus`, so the
# type came back as the empty set and the guard leaning on it was reported as
# `<unknown:skip_census>`: an honest refusal, but one that named the accessor
# rather than the type, so the reader could not tell "this predicate has no
# recipe" from "this tool cannot see the type". A borrowed threshold is exactly
# as mutable as an owned one; the borrow is a calling convention.
RETURNS = re.compile(r"\bfn\s+{name}\s*\(\s*&self\s*\)\s*->\s*&?(?:'\w+\s+)?([\w:]+)")
IMPL = re.compile(r"^impl(?:<[^>]*>)?\s+([A-Za-z_]\w*)", re.M)

# R311y862 — one term of a summing predicate: a bare `self.field` read and
# nothing else. See `unswept_summands` for why the test has to be this tight.
SUMMAND = re.compile(r"self\.\w+")

# Round 2012 (item 253) — ONE TERM OF A PREDICATE, whatever joins them.
#
# A field or accessor read on a receiver: `self.frames`, `s.expired`,
# `self.open_fragment_chains()`. The trailing `()` is part of the term because
# a recipe zeroes the CALL, not the name.
#
# Deliberately NOT anchored to `self`: `unfinished_fragment_chains` binds
# `let s = self.fragments.stats()` and adds `s.expired + s.evicted`, and those
# two are exactly the terms a recipe zeroes. A pattern that only saw `self.`
# would report that predicate as having one term (`self.open_fragment_chains`)
# and miss the two that a `let` had renamed.
TERM = re.compile(r"\b([a-z_]\w*)((?:\.\w+)+)(\(\))?")

# Receivers that name a NAMESPACE rather than a value, so a read through them
# is not a term this gate can ask a recipe to zero.
NOT_A_RECEIVER = frozenset({"crate", "core", "alloc", "std", "super"})


def _last_segment(path: str) -> str:
    return path.rsplit("::", 1)[-1]


_SOURCES: list[str] | None = None


def _crate_sources() -> list[str]:
    """Every crate source, read once. The type lookup runs per guard and this
    keeps it from re-reading the tree each time."""
    global _SOURCES
    if _SOURCES is None:
        _SOURCES = [
            p.read_text(encoding="utf-8", errors="replace")
            for p in sorted((REPO_ROOT / "crates").rglob("*.rs"))
            if "target" not in p.parts
        ]
    return _SOURCES


def accessor_types(accessor: str) -> set[str]:
    """Every type an accessor of this name is declared to return.

    ALL of them, not one: two structs in this tree answer to `gaps()`, and
    picking either would be this tool guessing which receiver a guard held.
    Requiring every candidate to be covered is the conservative direction.
    """
    pattern = re.compile(RETURNS.pattern.format(name=re.escape(accessor)))
    out: set[str] = set()
    for text in _crate_sources():
        for hit in pattern.finditer(text):
            out.add(_last_segment(hit.group(1)))
    return out


def recipe_types() -> set[tuple[str, str]]:
    """`(type, predicate)` for each recipe, read from its `impl` block."""
    out: set[tuple[str, str]] = set()
    for _label, rel, anchor, _old, _new in PREDICATES:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        if anchor not in text:
            continue
        at = text.index(anchor)
        name = re.search(r"fn (\w+)\(", anchor)
        impls = IMPL.findall(text[:at])
        if name and impls:
            out.add((impls[-1], name.group(1)))
    return out


def uncovered_calls(pristine: str) -> list[tuple[str, str, str, str]]:
    """`(variant, accessor, type, predicate)` for guards leaning on an unmutated
    threshold.

    EVERY guard is asked, not only the ones `boundary` cannot reach. R311y731
    filtered on reachability as a proxy for "depends on a predicate", and the
    two come apart the moment a guard has two clauses: `x > 0 && !y.is_clean()`
    is reached by `boundary` on the first half and its second half would never
    be asked about.
    """
    out: list[tuple[str, str, str, str]] = []
    for g in GUARD.finditer(pristine):
        calls = CALL.findall(g.group("cond"))
        if len(calls) < 2:
            continue
        accessor, predicate = calls[-2], calls[-1]
        for ty in accessor_types(accessor) or {f"<unknown:{accessor}>"}:
            if (ty, predicate) not in COVERED_TYPES:
                out.append((g.group("variant"), accessor, ty, predicate))
    return out


def result_expression(body: str) -> str:
    """A predicate body's RESULT, with its `let` bindings dropped.

    Round 2012 (item 253) — the bindings have to go or the reads that produce
    them are counted as terms. `unfinished_fragment_chains` opens with
    `let s = self.fragments.stats();`, and that call is how the terms are
    OBTAINED rather than one of them: no recipe zeroes it, and requiring one
    would be this gate inventing a finding.

    Split on `;` rather than parsed, which is enough because a predicate is one
    expression with at most a few bindings in front of it — and if one ever
    stops being that, the terms it reports change and a recipe has to be
    written, which is the direction this gate is meant to fail in.
    """
    statements = [s for s in body.split(";") if s.strip()]
    return statements[-1] if statements else ""


def predicate_terms(body: str) -> set[str]:
    """Every term a predicate's result reads, whatever operator joins them."""
    out: set[str] = set()
    for receiver, path, call in TERM.findall(result_expression(body)):
        if receiver in NOT_A_RECEIVER:
            continue
        out.add(f"{receiver}{path}{call}")
    return out


def unswept_summands() -> list[tuple[str, str]]:
    """`(anchor, term)` for every term a recipe-bearing predicate reads that no
    recipe touches.

    R311y862 — THE RECIPE LISTS ARE HAND-WRITTEN AND THE ACCESSORS THEY DESCRIBE
    ARE NOT. `SkipCensus::bytes_absent` grew a sixth field this round; the loop
    above names five, and nothing would have said so — the new counter would
    have been swept by no mutant while the gate reported OK, which is coverage
    claimed rather than measured. Exactly the shape this file exists to refuse,
    on the file itself.

    Read from the function body rather than from a second list, because a second
    list is the thing that just went stale.

    ## Round 2012 (item 253) — WHY THIS STOPPED BEING ABOUT SUMS

    It used to split the body on `+` and walk away unless EVERY chunk was a
    bare `self.field`. That test was written to keep `drops.any` — a `||`
    chain — from being reported as one enormous summand, and it worked, by
    declining to look at it at all. Measured before this round: of the SIX
    recipe-bearing predicates, exactly ONE reached the check. `drops.any` could
    grow a seventh disjunct and `unfinished_fragment_chains` a fourth term, and
    the gate would have reported OK about a counter nothing measured — which is
    the very sentence the paragraph above is written against.

    The operator was never the point. A predicate grows COVERAGE DEBT by
    growing a TERM, and `+`, `||` and `&&` are three spellings of that. So the
    terms are extracted from the result expression whatever joins them, and a
    term counts as covered when some recipe for that predicate MENTIONS it —
    `is_decisive`'s recipe rewrites `self.undecided == 0`, which is how it
    zeroes the term `self.undecided`, and a set difference over bare names
    would have called that uncovered.
    """
    out: list[tuple[str, str]] = []
    covered: dict[tuple[str, str], set[str]] = {}
    for _label, rel, anchor, old, _new in PREDICATES:
        covered.setdefault((rel, anchor), set()).add(old.strip())
    for (rel, anchor), recipes in covered.items():
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        if anchor not in text:
            continue
        at, end = _function_span(text, anchor)
        body = text[text.index("{", at) + 1 : end - 1]
        for term in sorted(predicate_terms(body)):
            if not any(term in recipe for recipe in recipes):
                out.append((anchor, term))
    return out


# Round 2012 (item 253) — THE TERM EXTRACTOR'S OWN TEST.
#
# R1994's lesson, applied where it was earned: a gate is code, and a gate with
# no test is a claim. This one is worth more than most, because its failure
# mode is SILENCE — a shape it cannot read is a predicate it declines to check,
# and declining looks exactly like passing. That is precisely how item 253
# survived: `unswept_summands` reported OK for two years while reaching one
# predicate out of six.
#
# `(label, body, expected terms)`. The bodies are the four real shapes plus the
# two the old splitter could not read, spelled out here so the extractor can be
# asked about them without a tree to read.
TERM_CASES = (
    (
        "a plain sum",
        "self.a + self.b + self.c",
        {"self.a", "self.b", "self.c"},
    ),
    (
        "an || chain -- what the sum splitter walked away from",
        "self.frames > 0\n || self.stream_bytes > 0\n || self.flows > 0",
        {"self.frames", "self.stream_bytes", "self.flows"},
    ),
    (
        "an && chain, which nothing had ever asked about",
        "self.opened && self.closed",
        {"self.opened", "self.closed"},
    ),
    (
        "a let binding: the bound call is NOT a term, the reads through it are",
        "let s = self.fragments.stats();\n s.expired + s.evicted + self.open()",
        {"s.expired", "s.evicted", "self.open()"},
    ),
    (
        "a comparison, whose term is the side that can grow",
        "self.undecided == 0",
        {"self.undecided"},
    ),
    (
        "a whole-value equality reads no field and has no term",
        "*self == Self::default()",
        set(),
    ),
    (
        "a path is a namespace, not a receiver",
        "self.n + crate::limits::FLOOR",
        {"self.n"},
    ),
)


def selftest() -> int:
    """Drive [`predicate_terms`] over the shapes above, both directions.

    The second direction is the half that matters and it is asserted at the
    end: a term NOT named by any recipe must be reported. A checker that
    returned the empty list for everything would pass every case above.
    """
    failures: list[str] = []
    for label, body, expected in TERM_CASES:
        got = predicate_terms(body)
        if got != expected:
            failures.append(f"  {label}: expected {sorted(expected)}, got {sorted(got)}")

    # The gate's own claim, driven rather than trusted: a term no recipe
    # mentions is REPORTED, and one a recipe mentions is not.
    terms = predicate_terms("self.a + self.b")
    recipes = {"self.a"}
    unswept = sorted(t for t in terms if not any(t in r for r in recipes))
    if unswept != ["self.b"]:
        failures.append(f"  coverage test: expected ['self.b'], got {unswept}")
    if [t for t in predicate_terms("self.a") if not any(t in r for r in {"self.a == 0"})]:
        failures.append("  coverage test: a recipe rewriting a COMPARISON must cover its term")

    if failures:
        print("verdict-leg mutation selftest: FAIL", file=sys.stderr)
        for f in failures:
            print(f, file=sys.stderr)
        return 1
    print(
        f"verdict-leg mutation selftest: OK — {len(TERM_CASES)} predicate "
        "shape(s) read, including the two the sum splitter could not"
    )
    return 0


def _function_span(text: str, anchor: str) -> tuple[int, int]:
    """Byte range of the function body opened by `anchor`."""
    at = text.index(anchor)
    depth, j = 0, text.index("{", at)
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return at, j + 1


def apply_predicate(text: str, anchor: str, old: str, new: str) -> str | None:
    """`text` with `old` -> `new` inside `anchor`'s function, or None if the
    recipe no longer describes the code."""
    if anchor not in text:
        return None
    if anchor == old:
        # The whole-function form: the anchor IS what gets replaced.
        return text.replace(old, new, 1) if text.count(old) == 1 else None
    start, end = _function_span(text, anchor)
    body = text[start:end]
    if body.count(old) != 1:
        return None
    return text[:start] + body.replace(old, new, 1) + text[end:]


# Name, mutation, what a survivor means, whether EVERY leg must be reachable.
#
# The third field is the sentence the failure prints, because "SURVIVED" means a
# different defect per operator and one generic message sends the reader to the
# wrong fix. The fourth separates two very different kinds of unreachability: a
# leg `sever` or `widen` cannot reach is a hole in this TOOL and fails the run,
# while a guard with no threshold in it is simply not a question `boundary` can
# ask -- reported by name, never silently skipped.
OPERATORS = (
    (
        "sever",
        sever,
        "every test passed with this leg SEVERED, so nothing in the suite "
        "depends on it being raised",
        True,
    ),
    (
        "widen",
        widen,
        "every test passed with this leg's guard WIDENED to always fire, so "
        "no test holds it quiet over a capture that is fine",
        True,
    ),
    (
        "boundary",
        boundary,
        "every test passed with this leg's threshold moved ONE step, so no "
        "fixture trips it with the smallest possible evidence -- a reader that "
        "stopped reporting the single-instance case would go unnoticed",
        False,
    ),
)

# How long one mutant's suite may take before this calls it hung. Generous --
# the point is to notice a mutant that never returns, not to police speed.
RUN_TIMEOUT_S = 900


def load_lint():
    """The static gate's parser, imported rather than rewritten.

    The population of legs must be the SAME population both gates check, and two
    parsers over one declaration is two chances to disagree about it.
    """
    spec = importlib.util.spec_from_file_location("verdict_reason_lint", LINT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def crate_of(rel_path: str) -> str | None:
    """The cargo package name owning `rel_path`, read from its own Cargo.toml."""
    at = (REPO_ROOT / rel_path).parent
    while at != REPO_ROOT and at != at.parent:
        manifest = at / "Cargo.toml"
        if manifest.is_file():
            hit = re.search(
                r"(?ms)^\[package\].*?^name\s*=\s*\"([^\"]+)\"",
                manifest.read_text(encoding="utf-8"),
            )
            if hit:
                return hit.group(1)
        at = at.parent
    return None


def run_suite(packages: list[str]) -> tuple[str, str]:
    """`(verdict, output)` where verdict is `green` / `red` / `uncompilable`.

    The three are told apart deliberately. `cargo test` exits non-zero for a
    failing test and for a source that does not build, and reading the second as
    the first would let this gate pass a leg on the strength of a syntax error.
    """
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(REPO_ROOT / TARGET_DIR)
    cmd = ["cargo", "test"]
    for p in packages:
        cmd += ["-p", p]
    try:
        done = subprocess.run(
            cmd,
            cwd=REPO_ROOT / "crates",
            env=env,
            capture_output=True,
            text=True,
            timeout=RUN_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return "hung", f"no result within {RUN_TIMEOUT_S}s"
    out = done.stdout + done.stderr
    # THE DISCRIMINATOR, and the first version of it was wrong in a way worth
    # recording: it read any line opening `error: ` as a build failure, and
    # `cargo test` prints `error: test failed, to rerun pass ...` for a FAILING
    # TEST. Every one of the twenty-three mutants was therefore reported
    # uncompilable. The gate failed closed, which is the right direction to be
    # wrong in, and it still measured nothing.
    #
    # `could not compile` is cargo's own words for a crate that did not build,
    # and it is printed for nothing else. Linking is separate and is not a
    # compile, so it is named separately rather than assumed to be covered.
    if "could not compile" in out or "error: linking with" in out:
        return "uncompilable", out
    if done.returncode == 0:
        return "green", out
    # A non-zero exit with no test report at all is neither a red test nor a
    # build failure -- a harness that could not start, a panic in a build
    # script. Reading it as `red` would credit the leg with a kill it did not
    # earn, which is the false pass this whole tool exists to refuse.
    if "test result:" not in out:
        return "unrun", out
    return "red", out


def failing_tests(output: str) -> list[str]:
    """The test names cargo listed under `failures:`, for the evidence line."""
    names: list[str] = []
    for block in re.findall(r"(?ms)^failures:\n(.*?)(?:\n\n|\Z)", output):
        for line in block.splitlines():
            line = line.strip()
            if line and not line.endswith(":") and " " not in line:
                names.append(line)
    return sorted(set(names))


def main() -> int:
    # `--only X` narrows the sweep to one leg. It exists for the probe that
    # keeps this gate honest -- weaken the single test that kills one mutant and
    # re-ask about THAT leg -- and re-running forty-six mutants to learn about
    # one is how a probe stops being run at all. It says PROBE in the headline
    # and in the OK line, because a partial population reporting a plain OK is
    # the population-of-zero green wearing this tool's own words.
    only: str | None = None
    argv = sys.argv[1:]
    while argv:
        arg = argv.pop(0)
        if arg == "--only" and argv:
            only = argv.pop(0)
        elif arg == "--selftest":
            # Round 2012 (item 253) — the term extractor asked about fixtures
            # rather than about the tree. Cheap, needs no build, and it is what
            # would have caught this gate reaching one predicate out of six.
            return selftest()
        else:
            print(
                f"usage: {Path(sys.argv[0]).name} [--only VARIANT] [--selftest]",
                file=sys.stderr,
            )
            return 2

    source_path = REPO_ROOT / SOURCE
    backup_path = REPO_ROOT / BACKUP
    if not source_path.is_file():
        print(
            f"verdict-leg mutation: FAIL — {SOURCE} is not there, so there are "
            "no legs to sever and this must not report OK.",
            file=sys.stderr,
        )
        return 1
    if backup_path.exists():
        print(
            f"verdict-leg mutation: FAIL — {BACKUP} exists, which means a "
            "previous run died with a MUTANT on disk. This tool will not guess "
            f"which copy is real. Compare it against {SOURCE}, restore by hand, "
            "delete the backup, and run again.",
            file=sys.stderr,
        )
        return 1

    pristine = source_path.read_text(encoding="utf-8")

    lint = load_lint()
    declared, _wire = lint.declared(pristine)
    pushes = PUSH.findall(pristine)
    raised = sorted({variant for _indent, variant in pushes})
    if not declared:
        print(
            "verdict-leg mutation: FAIL — the enum declaration did not parse. "
            "The population is read from it and a sweep with no population "
            "measures nothing.",
            file=sys.stderr,
        )
        return 1
    missing = sorted(set(declared) - set(raised))
    if missing:
        # A variant nothing raises is a leg no capture can reach: severing it
        # would change nothing, and reporting that as "not load-bearing" would
        # name the wrong defect.
        print("verdict-leg mutation: FAIL", file=sys.stderr)
        for v in missing:
            print(
                f"  `VerdictReason::{v}` is declared and `reasons()` never "
                "pushes it — no capture can raise this leg at all",
                file=sys.stderr,
            )
        return 1

    # Every leg must be reachable by BOTH operators before any of them runs.
    # Discovering half way through that a guard cannot be widened would leave
    # the run reporting on a population it never states.
    guarded = {m.group("variant") for m in GUARD.finditer(pristine)}
    unguarded = sorted(set(raised) - guarded)
    if unguarded:
        print("verdict-leg mutation: FAIL", file=sys.stderr)
        for v in unguarded:
            print(
                f"  `VerdictReason::{v}` is raised, but its guard is not a "
                "single-line `if COND {` directly above the push, so the "
                "`widen` operator cannot reach it",
                file=sys.stderr,
            )
        print(
            "\nThis is a failure of the SWEEP. Half a question asked in "
            "silence is the\npopulation-of-zero green this gate exists to "
            "refuse: either give the leg a\nsingle-line guard, or teach this "
            "tool the shape it now has.",
            file=sys.stderr,
        )
        return 1

    # Which packages to run. DERIVED from where the bindings actually are, so a
    # binding that moves to a new crate brings that crate into the sweep without
    # anyone editing a list here.
    bound, _tests, _files = lint.test_bindings(REPO_ROOT)
    crates_for: dict[str, list[str]] = {}
    for variant, sites in bound.items():
        crates_for[variant] = sorted(
            {crate for site in sites if (crate := crate_of(site.split("::", 1)[0]))}
        )
    packages = sorted({c for cs in crates_for.values() for c in cs})
    if not packages:
        print(
            "verdict-leg mutation: FAIL — no crate owns any binding, so the "
            "sweep would run no tests at all.",
            file=sys.stderr,
        )
        return 1

    # Every predicate an unreachable guard leans on must be one the recipes
    # mutate. Checked BEFORE anything runs, like every other population claim
    # in this file.
    # And a declaration cannot outrun the recipe it claims. Every pair in
    # COVERED_CALLS must name a predicate some recipe actually mutates,
    # otherwise the declaration silences the check while nothing is swept --
    # the same failure the register's stale check exists to stop, on the other
    # side of the same list.
    declared = recipe_types()
    orphan_pairs = sorted(COVERED_TYPES - declared)
    if orphan_pairs:
        print("verdict-leg mutation: FAIL", file=sys.stderr)
        for ty, pred in orphan_pairs:
            print(
                f"  COVERED_TYPES declares `{ty}::{pred}` covered, and no "
                "recipe mutates it",
                file=sys.stderr,
            )
        return 1

    # R311y862 — and a recipe LIST cannot outrun the accessor it describes,
    # which is the same failure one level in: the pairs above are declared by
    # hand and so are the fields, and a summing predicate that grows a term
    # nobody zeroes is a counter this sweep silently stops asking about.
    unswept = unswept_summands()
    if unswept:
        print("verdict-leg mutation: FAIL", file=sys.stderr)
        for anchor, term in unswept:
            print(
                f"  `{anchor.strip()}` reads `{term}`, and no recipe zeroes it "
                "-- the sweep would report OK while that counter is measured "
                "by nothing",
                file=sys.stderr,
            )
        print(
            "\nAdd it to that predicate's recipe loop in PREDICATES. A term "
            "added to a\nverdict predicate is a new way for the capture to be "
            "short, and the question\nthis gate asks is whether anything "
            "notices. Round 2012 (item 253) — `reads`\nand not `sums`: the "
            "check no longer walks away from a predicate whose terms\nare "
            "joined by `||` or `&&` rather than by `+`.",
            file=sys.stderr,
        )
        return 1

    uncovered = uncovered_calls(pristine)
    if uncovered:
        print("verdict-leg mutation: FAIL", file=sys.stderr)
        for variant, accessor, ty, predicate in uncovered:
            print(
                f"  `VerdictReason::{variant}` guards on "
                f"`{accessor}().{predicate}()`, which reaches `{ty}` -- a "
                "threshold this sweep does not mutate and is not in "
                "COVERED_TYPES",
                file=sys.stderr,
            )
        print(
            "\nThe threshold this guard depends on lives inside that "
            "predicate, one level\ndown. Add a recipe for it to PREDICATES "
            "and declare the (type, predicate) pair\nin COVERED_TYPES. "
            "Silence here reads as coverage.",
            file=sys.stderr,
        )
        return 1

    if only is not None:
        if only not in raised:
            print(
                f"verdict-leg mutation: FAIL — `--only {only}` names no leg "
                f"`reasons()` raises. The population is {', '.join(raised)}.",
                file=sys.stderr,
            )
            return 1
        raised = [only]

    # Every file this run can touch, held together. R311y729 (N20) added the
    # predicate layer, which mutates three files outside `report.rs`, and a
    # restore that covered only the first would leave the others rewritten.
    touched = [SOURCE] + sorted({Path(rel) for _l, rel, *_r in PREDICATES})
    pristine_of = {
        rel: (REPO_ROOT / rel).read_text(encoding="utf-8") for rel in touched
    }
    backup_of = {
        rel: backup_path.parent / (str(rel).replace("/", "__") + ".pristine")
        for rel in touched
    }
    for rel, bk in backup_of.items():
        if bk.exists():
            print(
                f"verdict-leg mutation: FAIL — {bk} exists, which means a "
                "previous run died with a MUTANT on disk. Compare it against "
                f"{rel}, restore by hand, delete the backup, and run again.",
                file=sys.stderr,
            )
            return 1

    backup_path.parent.mkdir(parents=True, exist_ok=True)
    for rel, bk in backup_of.items():
        shutil.copy2(REPO_ROOT / rel, bk)
    survivors: list[tuple[str, str, str]] = []
    broken: list[tuple[str, str, str]] = []
    unasked: list[tuple[str, str]] = []
    registered: list[tuple[str, str]] = []
    evidence: dict[tuple[str, str], list[str]] = {}
    try:
        print(
            ("verdict-leg mutation PROBE: " if only else "verdict-leg mutation: ")
            + f"{len(raised)} leg(s) × {len(OPERATORS)} operator(s), suite = "
            + " ".join(packages),
            flush=True,
        )
        verdict, output = run_suite(packages)
        if verdict != "green":
            print(
                "verdict-leg mutation: FAIL — the UNMUTATED tree is not green "
                f"({verdict}). Over a red tree every mutant is red and this "
                "sweep would report every leg load-bearing while measuring "
                "nothing.\n" + output[-4000:],
                file=sys.stderr,
            )
            return 1
        # The baseline also PROVES the discriminator: a green here means the
        # unmutated suite was run and read as green, so a later `red` is this
        # tool telling two states apart rather than always saying one of them.
        if "test result:" not in output:
            print(
                "verdict-leg mutation: FAIL — the baseline run produced no "
                "`test result:` line, so nothing was actually run and every "
                "verdict below would be about an empty suite.",
                file=sys.stderr,
            )
            return 1
        print("  baseline green", flush=True)

        for variant in raised:
            for op_name, mutate, survived_means, must_reach in OPERATORS:
                mutant = mutate(pristine, variant)
                if mutant is None:
                    # Not a question this operator can ask of this guard.
                    unasked.append((variant, op_name))
                    continue
                if mutant == pristine:
                    broken.append(
                        (variant, op_name, f"the `{op_name}` produced no change")
                    )
                    continue
                source_path.write_text(mutant, encoding="utf-8")
                # The crates whose tests NAME this leg go first. A kill found in
                # a subset is a kill: running fewer tests can only make a mutant
                # harder to catch, never easier, so a red here is proof and a
                # green here is not yet an answer. Twenty of the twenty-three
                # legs are named only inside `wz-capture`, and asking about
                # those without rebuilding the reader is most of this sweep's
                # wall clock.
                narrow = crates_for.get(variant) or packages
                ran = narrow
                verdict, output = run_suite(narrow)
                if verdict == "green" and narrow != packages:
                    # ESCALATION, and it is what keeps the narrowing honest: a
                    # leg that survives its own crate might still be depended on
                    # by a test that never names it, and calling that a survivor
                    # would be this tool reporting a defect it manufactured.
                    #
                    # R311y727 — and the evidence line now names the set that
                    # ACTUALLY ran. It used to print `narrow` either way, so an
                    # escalated kill was reported against a package set the
                    # killing test is not even in. Measured, not reasoned: a
                    # probe here printed a `wz-replay` test as killed "in
                    # wz-capture".
                    ran = packages
                    verdict, output = run_suite(packages)
                if verdict == "uncompilable":
                    broken.append(
                        (
                            variant,
                            op_name,
                            f"the mutant does not compile\n{output[-1500:]}",
                        )
                    )
                elif verdict in ("hung", "unrun"):
                    broken.append((variant, op_name, f"{verdict}: {output[-1500:]}"))
                elif verdict == "green":
                    survivors.append((variant, op_name, survived_means))
                    print(f"  {variant} [{op_name}]: SURVIVED", flush=True)
                else:
                    names = failing_tests(output)
                    evidence[(variant, op_name)] = names
                    print(
                        f"  {variant} [{op_name}]: killed by {len(names)} "
                        f"test(s) in {' '.join(ran)}"
                        + (f" (e.g. {names[0]})" if names else ""),
                        flush=True,
                    )

        # ─── The predicate layer (N20) ───────────────────────────────
        #
        # `report.rs` FIRST, because the loop above leaves its LAST mutant on
        # disk and every predicate mutant would then be measured on top of it.
        # This was not reasoned about -- the first run reported all fifteen
        # predicate mutants killed, and running one by hand showed zero failing
        # tests. The kills were the leftover leg mutant, not the predicate: a
        # gate reporting green for a reason that has nothing to do with what it
        # claims to measure.
        source_path.write_text(pristine, encoding="utf-8")
        #
        # Reported apart from the legs because the UNIT is different: a
        # threshold here belongs to a predicate that several legs share, so a
        # kill says "some test depends on this threshold", not "this leg is
        # pinned at its boundary". Conflating the two would claim a precision
        # this does not have.
        if PREDICATES:
            print(
                f"  predicate thresholds: {len(PREDICATES)} mutant(s), one "
                "step each",
                flush=True,
            )
        for label, rel, p_anchor, p_old, p_new in PREDICATES:
            at = REPO_ROOT / Path(rel)
            base = pristine_of[Path(rel)]
            mutant = apply_predicate(base, p_anchor, p_old, p_new)
            if mutant is None or mutant == base:
                broken.append(
                    (
                        label,
                        "predicate",
                        "the recipe no longer describes the code -- the "
                        "predicate moved and a stale recipe mutates nothing",
                    )
                )
                continue
            at.write_text(mutant, encoding="utf-8")
            verdict, output = run_suite(packages)
            at.write_text(base, encoding="utf-8")
            if verdict == "uncompilable":
                broken.append(
                    (label, "predicate", f"the mutant does not compile\n{output[-1500:]}")
                )
            elif verdict in ("hung", "unrun"):
                broken.append((label, "predicate", f"{verdict}: {output[-1500:]}"))
            elif verdict == "green":
                if label in UNWITNESSED:
                    registered.append((label, UNWITNESSED[label]))
                    print(
                        f"  {label} [predicate]: unwitnessed (registered)",
                        flush=True,
                    )
                else:
                    survivors.append(
                        (
                            label,
                            "predicate",
                            "every test passed with this predicate forgiving "
                            "ONE -- no fixture reaches this counter at a "
                            "single instance, and it is not registered as "
                            "unwitnessed",
                        )
                    )
                    print(f"  {label} [predicate]: SURVIVED", flush=True)
            else:
                names = failing_tests(output)
                evidence[(label, "predicate")] = names
                print(
                    f"  {label} [predicate]: killed by {len(names)} test(s)"
                    + (f" (e.g. {names[0]})" if names else ""),
                    flush=True,
                )

    finally:
        for rel, text in pristine_of.items():
            at = REPO_ROOT / rel
            at.write_text(text, encoding="utf-8")
            if at.read_text(encoding="utf-8") != text:
                print(
                    f"verdict-leg mutation: FAIL — {rel} did not restore to "
                    f"its original bytes. The backup is at {backup_of[rel]}; "
                    "restore it by hand.",
                    file=sys.stderr,
                )
                return 1
        for bk in backup_of.values():
            bk.unlink(missing_ok=True)

    stale = sorted(set(UNWITNESSED) - {lbl for lbl, _r, *_x in PREDICATES})
    if stale:
        print("verdict-leg mutation: FAIL", file=sys.stderr)
        for lbl in stale:
            print(
                f"  `{lbl}` is registered as unwitnessed and is not a "
                "predicate this sweep mutates -- the register has outlived "
                "the recipe it excuses",
                file=sys.stderr,
            )
        return 1

    if registered:
        print(
            # R311y860 — no longer "each awaiting a fixture". Two of these are
            # UNREACHABLE rather than unbuilt, and a summary that told a reader
            # to go write a test for a counter no code path sets would be this
            # tool's own prose outliving the register beneath it. Each entry
            # states its own class; the heading stops asserting one for all.
            f"  {len(registered)} predicate threshold(s) REGISTERED as "
            "unwitnessed, each with the class it is in:",
            flush=True,
        )
        for lbl, why in registered:
            print(f"    {lbl} — {why}", flush=True)

    if unasked:
        # Printed on the way to OK, never instead of it. An operator that
        # cannot reach a guard has to say so out loud: a summary that counted
        # only what it asked would read as coverage it does not have.
        by_op: dict[str, list[str]] = {}
        for variant, op_name in unasked:
            by_op.setdefault(op_name, []).append(variant)
        for op_name, variants in sorted(by_op.items()):
            print(
                f"  [{op_name}] NOT ASKED of {len(variants)} leg(s) whose "
                "guard holds no threshold to move: " + ", ".join(sorted(variants)),
                flush=True,
            )

    if broken:
        print("verdict-leg mutation: FAIL", file=sys.stderr)
        for variant, op_name, why in broken:
            print(f"  `VerdictReason::{variant}` [{op_name}]: {why}", file=sys.stderr)
        print(
            "\nA mutant that does not build proves nothing about the leg. This "
            "is a\nfailure of the SWEEP, not a finding about the code: the "
            "mutation has to be\nexpressible before the question can be asked.",
            file=sys.stderr,
        )
        return 1
    if survivors:
        print("verdict-leg mutation: FAIL", file=sys.stderr)
        for variant, op_name, survived_means in survivors:
            print(
                f"  `VerdictReason::{variant}` [{op_name}] SURVIVED — "
                f"{survived_means}",
                file=sys.stderr,
            )
        print(
            "\nA leg surviving `sever` can be deleted and no one will know; "
            "R311y715 measured\nnine such guards at once. Bind it with a "
            "fixture that raises the reason and\nasserts it BY NAME — "
            "`reasons() == vec![VerdictReason::X]`.\n\n"
            "A leg surviving `widen` fires on every capture in the tree "
            "unnoticed, so the\nverdict can start crying incomplete over "
            "whole captures in silence. Bind it\nwith a fixture that is FINE "
            "in this respect and assert the reason is ABSENT —\n"
            "`assert!(!report.reasons().contains(&VerdictReason::X))`.",
            file=sys.stderr,
        )
        return 1

    least = min(len(v) for v in evidence.values()) if evidence else 0
    ops = ", ".join(name for name, _fn, _why, _reach in OPERATORS)
    print(
        ("verdict-leg mutation PROBE: OK for " if only else "verdict-leg mutation: OK (")
        + f"{len(raised)} leg(s) × {len(OPERATORS)} operator(s) [{ops}] = "
        f"{len(evidence)} mutant(s) asked"
        + (f" (incl. {len(PREDICATES)} predicate threshold(s))" if PREDICATES else "")
        + (f", {len(unasked)} not applicable" if unasked else "")
        + f", every one killed by at least {least} test(s); "
        f"suite = {' '.join(packages)}"
        + (
            " — A PARTIAL POPULATION: this says nothing about the other legs"
            if only
            else ")"
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
