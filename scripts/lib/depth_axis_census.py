#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2218 (no register item) — WHAT THE 86 PARTIAL GRADES ACTUALLY SAY, as three
numbers a command produces rather than a sentence somebody wrote once.

Answers item 200 of the unregistered register, which lives outside this
repository -- the position `debt_plane_census.py` and `armed_oracle_census.py`
already record for themselves. Item 200 reads:

    the BREADTH is closed and there is NO INSTRUMENT for the DEPTH ... the only
    tool is the A3 grade, which only a whole-surface re-audit overturns and no
    round does one ... so 85 is a BOOKKEEPING CONVENTION rather than the amount
    of work left.

## THE ITEM'S SHARPEST SENTENCE DID NOT REPRODUCE, and that is this file's
## first finding

Three hypotheses were probed before anything was built, and all three failed:

  * "PARTIAL is an unexamined label" -- FALSE. Every one of the 74 PARTIAL
    atoms an executing test reaches names a RESIDUAL in its own reason. Not one
    is a bare grade.
  * "the residual statements have rotted" -- FALSE. Those reasons carry 1003
    file citations; 409 resolve uniquely to a tracked wz path and NOT ONE has a
    line number past its file's end.
  * "the depth axis has no instrument at all" -- FALSE for configuration.
    `every_honoured_key_is_classified_by_what_proves_its_effect` already
    partitions all 37 honoured keys into wire / no-sink / argv-only, and its
    own doc says it was built for exactly this complaint.

⚠ A probe of the whole set found a defect in ITSELF first, and the shape is
worth carrying: matching a citation to a wz file by BASENAME resolved
`zenoh-config/src/lib.rs` onto `crates/wz-statechart-bridge/src/lib.rs` and
reported 87 out-of-bounds lines that were pure artefact. Suffix matching on the
full cited path gives 0. A loose matcher does not fail loudly; it produces a
confident wrong number.

## So what IS missing, and what this file is

Nothing measured any of the above. The numbers were true and unwatched, which
is the state item 200 describes even though its diagnosis of WHY was wrong. So
this is the depth census in the shape item 200 itself named as the next
instrument -- y842's config census applied one axis over: a denominator the
tree derives, a numerator it derives, and the remainder pinned as a SET.

⛔ A THIRD AXIS WAS BUILT AND THEN REMOVED, and the removal is the sharper
lesson. It asked whether each PARTIAL reason NAMES A RESIDUAL, and on its first
run it flagged `platform-macos` and `platform-windows`. Reading them showed the
flag was the axis's fault: both reasons are dense with state -- each carries a
CORRECTION recording that its own blocker turned out to be FALSE -- and they
merely spell it in words the axis had not been given. That axis was a KEYWORD
SWEEP wearing a gate's clothes, and open-debt item 190 already records that a
keyword sweep is structurally a FLOOR. A vocabulary of accepted words is an
exemption list with the polarity reversed, so it went out rather than growing.
What it noticed is worth a reader's attention and is recorded in the ledger as
an observation, which is where an unmeasured thing belongs.

Two axes, each a partition with no exempt bucket:

  REACH     Every PARTIAL atom, by whether an executing test names a symbol its
            own `cfg` gates -- `atom_test_graph`'s derivation, which
            `audit-catalog-status.sh` already trusts for COMPLETE and has never
            asked of PARTIAL. Three classes: reached, owned-but-unreached, and
            no-owned-symbol (the derivation declining to answer, which is
            counted rather than hidden).

  CITATION  Every wz-path file citation in a PARTIAL reason resolves to exactly
            one tracked file, and any line number it carries is inside that
            file. Upstream citations are counted apart and NOT judged -- R2215
            measured why nothing here can judge them: the vendored trees are
            submodules whose contents are not tracked files, and `.gitmodules`
            does not name zenoh at all.

## The pins, and why every one of them is two-directional

Each axis is pinned at what it measures today and the pin is enforced in BOTH
directions, on `C1bz`'s contract: a count that rises is something this change
added, and one that falls is something it repaired -- which lowers the pin in
that same commit. A one-directional pin is a number nobody has to keep true.

⚠ The pins are NOT a pass. A PARTIAL atom an executing test reaches is one
whose grade rests on its stated residual and on nothing else, and that is 74 of
86. Moving one of those to COMPLETE is the work; this file makes the size of it
a number, which is all item 200 asked for and all this can honestly give.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import atom_test_graph  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
STORE = "docs/.atomic/workspace.atomic.json"

# The inventory holds three kinds under one prefix space. An ATOM is defined by
# exclusion, exactly as `inventory_kinds.is_atom` defines it -- restated here
# rather than imported because that module reaches the store through
# `mnemosyne-cli`, and this gate reads the tracked file so Layer C0 needs no
# binary. The two prefixes are the same two.
PRESET_PREFIX = "preset-"
DEBT_PREFIX = "debt-"

# The head token of a reason is its TAG. Taken from `inventory_kinds`'s own
# rule: a tag is a SLOT, never a word that happens to occur later -- a reason
# routinely discusses the grades it does not carry.
HEAD_TAG = re.compile(r"\s*([A-Za-z][A-Za-z0-9-]*)")

# A file citation, with an optional line. The path may carry directories, and
# it MUST, for the reason the header gives: a bare basename matched against
# this tree resolves an upstream file onto an unrelated wz one.
CITATION = re.compile(r"\b((?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:rs|c|h))(?::(\d+))?")

# R2218 — pinned at what the tree measures today. Two-directional; see header.
#
# R2219 — 74 -> 73, and it is the first time this pin has moved for the reason
# the header says it should: `scouting-responder` left PARTIAL for COMPLETE
# because its ONE named residual was CLOSED, not relabelled. Upstream elects the
# reply's source socket by longest-octet match against the asker
# (`get_best_match`, zenoh `net/runtime/orchestrator.rs:1113-1134`) and wz
# answered from the group socket it received on; it now elects, the demo binds
# the sockets to elect from, and a Layer M leg watches two askers on two
# addresses each get the nearer one. The total falls with it, 86 -> 85.
#
# R2220 — 73 -> 72, the second move, for the same reason: `routing-namespace`'s
# residual was ONE named axis (the per-message-type diff against upstream
# `net/routing/namespace.rs`), that diff was walked arm for arm, and the two
# gaps it found were CLOSED rather than re-described. The total falls with it,
# 85 -> 84, and the citation pin below falls because that reason's two wz
# citations left the PARTIAL corpus with it.
# R2333 — 407 -> 405 and 86 -> 85, and NEITHER move is this round's own work.
# The measurement moved in R2332 (`transport-stats cited a zenoh file gone at
# the pin`), which re-cited that atom's reason and did not move the pins with
# it; the ratchet caught it exactly as designed, on the next run. The pins move
# here because this is the commit that publishes that one.
#
# What left, read out of the two revisions rather than inferred: the reason
# dropped `wz-session-core/src/stats.rs` for the repo-rooted
# `crates/wz-session-core/src/stats.rs` (still one wz citation, so no move from
# that pair), dropped the four line-form citations `drive.rs:76`,
# `session_actions.rs:1426`, `stats.rs:34` and `stats.rs:50`, and gained two
# rooted UPSTREAM paths (read as upstream, not judged) plus a bare `stats.rs`.
# Two wz citations and one ambiguous one net out of the corpus.
#
# Those two upstream paths are deliberately NOT spelled here. Writing them would
# make this comment itself an upstream citation in bare form, which is the
# R2241 class -- `upstream_citation_anchor_gate.py` counted exactly that and
# redded on 60 -> 62 while this note was being written. A gate's own prose is
# tracked text like any other; the repair is to stop making the claim, not to
# re-anchor a claim this file has no reason to make.
PIN_REACHED = 72
PIN_UNREACHED = 2
PIN_NO_SYMBOL = 10
PIN_WZ_CITATIONS = 405
PIN_AMBIGUOUS = 85


class Fatal(Exception):
    """A derivation that cannot be made. Never a silent pass."""


def tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [p for p in out.split("\0") if p]


def partial_atoms() -> dict[str, str]:
    """`{atom id: reason}` for every atom the inventory grades PARTIAL.

    Read from the TRACKED store rather than through `mnemosyne-cli`: the file
    is the SSOT either way and reading it keeps this gate runnable wherever
    Layer C0 runs, with no binary to install first.
    """
    try:
        data = json.loads((ROOT / STORE).read_text())
    except (OSError, ValueError) as exc:
        raise Fatal(f"the inventory store {STORE} could not be read ({exc})") from exc
    entries = data.get("inventory_entries")
    if not isinstance(entries, dict):
        raise Fatal(f"{STORE} holds no `inventory_entries` mapping.")
    out: dict[str, str] = {}
    for eid, entry in entries.items():
        if eid.startswith(PRESET_PREFIX) or eid.startswith(DEBT_PREFIX):
            continue
        reason = (entry or {}).get("reason") or ""
        head = HEAD_TAG.match(reason)
        if head and head.group(1).upper() == "PARTIAL":
            out[eid] = reason
    if not out:
        raise Fatal(
            "no atom is graded PARTIAL. Every axis below would report zero of "
            "zero, which reads exactly like a clean surface."
        )
    return out


def reach_partition(reasons: dict[str, str]) -> dict[str, list[str]]:
    """PARTIAL atoms split by whether an executing test reaches their code.

    The join is `atom_test_graph`'s and is not re-derived here: that module
    evaluates each `cfg` as a BOOLEAN so an `any(..)` OR-contributor does not
    count as owning shared plumbing, and resolves the gated symbol before
    looking for test references. `audit-catalog-status.sh` already trusts it
    for COMPLETE; this asks it the question nobody asked of PARTIAL.
    """
    graph = atom_test_graph.graph()
    out: dict[str, list[str]] = {"reached": [], "unreached": [], "no_symbol": []}
    for atom in sorted(reasons):
        owned, referenced = graph.get(atom, (set(), set()))
        if not owned:
            out["no_symbol"].append(atom)
        elif referenced:
            out["reached"].append(atom)
        else:
            out["unreached"].append(atom)
    return out


def citation_audit(
    reasons: dict[str, str], paths: list[str]
) -> tuple[int, int, int, list[str]]:
    """(wz citations, ambiguous, upstream, findings).

    A citation resolves when exactly one tracked path ENDS WITH the cited path.
    Several candidates is ambiguity and is counted, never guessed at; none is
    read as upstream and left unjudged, which is the honest verdict R2215
    measured rather than a shrug.
    """
    unique = ambiguous = upstream = 0
    findings: list[str] = []
    for atom in sorted(reasons):
        for match in CITATION.finditer(reasons[atom]):
            cited, line = match.group(1), match.group(2)
            if cited in paths:
                candidates = [cited]
            else:
                candidates = [p for p in paths if p.endswith("/" + cited)]
            if not candidates:
                upstream += 1
                continue
            if len(candidates) > 1:
                ambiguous += 1
                continue
            unique += 1
            if line is None:
                continue
            try:
                length = len((ROOT / candidates[0]).read_text(errors="replace").split("\n"))
            except OSError:
                findings.append(
                    f"{atom}: cites `{cited}:{line}` and that tracked file cannot be read"
                )
                continue
            if int(line) > length:
                findings.append(
                    f"{atom}: cites `{cited}:{line}` and {candidates[0]} has "
                    f"{length} line(s) -- the residual points past the end of "
                    f"its own evidence."
                )
    return unique, ambiguous, upstream, findings


def run() -> int:
    reasons = partial_atoms()
    paths = tracked()
    reach = reach_partition(reasons)
    unique, ambiguous, upstream, findings = citation_audit(reasons, paths)

    print(
        f"depth-axis-census: {len(reasons)} atom(s) graded PARTIAL -- "
        f"{len(reach['reached'])} reached by an executing test, "
        f"{len(reach['unreached'])} owned but unreached, "
        f"{len(reach['no_symbol'])} with no symbol the derivation can own"
    )
    print(
        f"  citations: {unique} resolve to one tracked wz file, "
        f"{ambiguous} ambiguous, {upstream} read as upstream and NOT judged "
        f"(R2215: this tree holds no oracle for them)"
    )

    for label, actual, pin in (
        ("reached", len(reach["reached"]), PIN_REACHED),
        ("unreached", len(reach["unreached"]), PIN_UNREACHED),
        ("no-symbol", len(reach["no_symbol"]), PIN_NO_SYMBOL),
        ("wz citations", unique, PIN_WZ_CITATIONS),
        ("ambiguous citations", ambiguous, PIN_AMBIGUOUS),
    ):
        if actual != pin:
            direction = "rose" if actual > pin else "fell"
            findings.append(
                f"{label}: {actual} against a pin of {pin} -- the count {direction}. "
                f"A pin moves in the commit that moves the measurement, and the "
                f"commit says which atom and why."
            )
    if findings:
        print("depth-axis-census: FAIL", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print(
        f"  {unique} wz citation(s) resolve and none points past its file's end"
    )
    return 0


def selftest() -> int:
    def fail(message: str) -> int:
        print(f"depth-axis-census: SELFTEST FAIL -- {message}", file=sys.stderr)
        return 1

    # The head tag is a SLOT. A reason that DISCUSSES another grade must not be
    # read as carrying it -- the defect `inventory_kinds` records for itself.
    if HEAD_TAG.match("COMPLETE: mentions PARTIAL later").group(1) != "COMPLETE":
        return fail("the head tag was read from the wrong token")
    if HEAD_TAG.match("PARTIAL: F=x").group(1) != "PARTIAL":
        return fail("a plain PARTIAL head did not read as one")

    # ⚠ THE MATCHER CONTROL, and it is the trap this round fell into first.
    # A cited upstream path must NOT resolve onto a wz file that merely shares
    # its basename.
    paths = ["crates/wz-statechart-bridge/src/lib.rs", "crates/wz-capture/src/agg.rs"]
    reasons = {"probe": "RESIDUAL vs zenoh: zenoh-config/src/lib.rs:362 differs"}
    unique, ambiguous, upstream, findings = citation_audit(reasons, paths)
    if (unique, upstream) != (0, 1) or findings:
        return fail(
            f"an upstream path resolved onto a wz file: unique={unique} "
            f"upstream={upstream} findings={findings}"
        )

    # A real wz citation resolves, and one past the end is a finding.
    real = "crates/wz-capture/src/agg.rs"
    length = len((ROOT / real).read_text(errors="replace").split("\n"))
    good = {"probe": f"RESIDUAL: see {real}:1 for the seam"}
    unique, _amb, _up, findings = citation_audit(good, [real])
    if unique != 1 or findings:
        return fail(f"a real wz citation did not resolve cleanly: {findings}")
    bad = {"probe": f"RESIDUAL: see {real}:{length + 500} for the seam"}
    _u, _a, _p, findings = citation_audit(bad, [real])
    if not findings:
        return fail("a citation past the end of its file produced no finding")

    # An AMBIGUOUS citation is counted, never guessed at: two tracked files
    # ending in the cited path is exactly the state the basename matcher
    # resolved by picking one.
    twin = ["crates/a/src/lib.rs", "crates/b/src/lib.rs"]
    _u, amb, _p, findings = citation_audit({"probe": "RESIDUAL: src/lib.rs:1"}, twin)
    if amb != 1 or findings:
        return fail(f"an ambiguous citation was resolved instead of counted: {amb}")

    print("depth-axis-census: selftest OK (8 derivations driven)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="what the PARTIAL grades say, as numbers rather than a sentence"
    )
    parser.add_argument("--selftest", action="store_true", help="drive each derivation")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    try:
        return run()
    except Fatal as exc:
        print(f"depth-axis-census: FAIL -- {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
