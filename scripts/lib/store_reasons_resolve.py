#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2337 (no register item) — an atom's claim about upstream must still be TRUE
at the pin, and the store is where those claims live.

The citation is `no register item` in the sense `upstream_citation_anchor_gate.py`
uses: the item this answers -- item 15, the PARTIAL-atom track, taken on its
atom `routing-router` -- lives in the agent-memory register outside this tree
and has no store `debt-` id for `gate_provenance_lint.py` to resolve. It is
named in prose here instead.

## The blind spot, measured rather than argued

`upstream_citation_anchor_gate.py` grades every upstream claim in this tree
against the pinned checkout -- 670 citations across 1175 tracked files. Its
population is `git ls-files` minus `SKIP_PREFIXES`, and one of those prefixes is
the atomic store. The reason recorded there is exact and correct as far as it
goes: the store's LEDGER quotes citations verbatim, so scanning it would grade
history. A frozen changelog entry that quoted a citation true in 2026-06 must
not red because upstream moved in 2026-09.

But the store holds TWO populations under that one prefix, and they have
opposite properties:

  * `changelog_entries` -- frozen. History. Must not be graded. The exclusion
    is right about these, and this gate never reads them.
  * `inventory_entries[*].reason` -- LIVE. Each one states what remains for an
    atom to reach parity, it is the input every grading round reads, and the
    convention is that it is APPENDED to. It is not history; it is the standing
    claim.

One blanket path exclusion, two populations, and the live one -- the SSOT for
what parity still owes -- was graded by nothing at all.

What that cost, measured on the atom this round took: `routing-router`'s
residual list debits wz for having no peers-failover brokering, citing three
files under the router hat. The paths still exist at the pin, so nothing that
checks paths would notice; the CAPABILITY does not. Upstream deleted it. The
whole `hat/` tree of the pinned checkout contains zero occurrences of either
word, and the config key that drove it is a deprecated shim upstream documents
as having no effect. The claim had become a debit against wz for a capability
zenoh itself no longer has -- the exact harm R2230 built the extension list to
prevent, one layer up, in the file no instrument reads.

## The third direction, and why the tree did not have it

The anchor gate has two forms and they point opposite ways:

    `path` @ `needle`   -- the path exists AND the needle occurs in it
    `path` @ REMOVED    -- no file at the pin has that path

Between them sits the case that actually happens when upstream refactors: THE
FILE SURVIVES AND THE THING IN IT DOES NOT. A capability is dropped, its module
keeps its name and its other contents, and every citation to it still resolves
as a path. `@ REMOVED` is false for it (the path is there) and the anchor form
is false for it (the needle is not). So the claim can only be written in a form
nothing grades, which is how it survived.

    `path` @ ABSENT `needle`   -- the path exists AND the needle does NOT

RED when the needle REAPPEARS. That is the point, and it is the same property
the other two forms have pointed in the third direction: if upstream re-adds
failover brokering, the withdrawn residual becomes true again and says so
without anyone remembering to look.

`@ ABSENT` was chosen the way `@` and `@ REMOVED` were -- measured across the
tracked tree before use, zero occurrences, so no legacy sentence can be read as
one. (`@ NONE`, `@ GONE` and `@ NOTIN` are equally free; ABSENT was taken
because it names the needle's state rather than an event, which is what
distinguishes it from `@ REMOVED`.)

## Why this is a SEPARATE gate and not a widened SKIP_PREFIXES

Dropping `docs/.atomic/` from that tuple would grade the ledger, which the
exclusion is right to refuse, and would drag the store's legacy `path:line`
mentions into ratchets that the append-only convention makes unpayable -- a
reason is corrected by APPENDING, so the original line-form citation can never
be removed, and a shrink-only budget over it is red forever with no legal move.
R2335 walked into exactly that shape and recorded it.

So the seam is the DATA, not the path: this gate parses the store as JSON and
reads one field of one collection. The ledger is not skipped by a prefix here,
it is never reached. And only the ANCHORED forms are graded -- legacy prose in
a reason is invisible to this gate, so adopting an anchor stays a per-round,
per-atom move that an appended correction can make.

## The floors

Three, and each is exercised on its own by the selftest, because a floor that
is only ever tested alongside another cannot be shown to fire by itself:

  * reasons parsed == 0     -> rc 2. The store moved or the field was renamed;
                               nothing was graded and this must not read green.
  * claims found == 0       -> rc 1. The forms went unused; the gate has no
                               subject.
  * ABSENT claims == 0      -> rc 1. The arm this gate exists for has no
                               subject. A round that removes the last one is
                               removing the discriminator, and that should cost
                               a deliberate edit here rather than passing quietly.

## The R2241 class

This file is tracked, so it is inside the population `upstream_citation_anchor_gate`
scans, and a real upstream path written here would become a citation of its own
-- the defect that has now recurred five times, most recently in the gate R2336
wrote for the layer below this one. So NO upstream path literal appears in this
file. The scanner takes its root list as an argument, the selftest passes a
synthetic root that names no real upstream directory, and the live run takes the
real roots from `upstream_citation_anchor_gate.UPSTREAM_ROOTS` -- one source,
read directly, never transcribed.
"""

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import upstream_citation_anchor_gate as anchor  # noqa: E402 -- after the path insert

#: The store, and the ONE collection inside it this gate reads. Naming the
#: collection here rather than scanning the file is what keeps the frozen
#: ledger out of reach by construction instead of by a filter someone can widen.
STORE_REL = pathlib.Path("docs") / ".atomic" / "workspace.atomic.json"
INVENTORY_KEY = "inventory_entries"
REASON_KEY = "reason"

#: Below this, assume the store shape moved rather than that the tree really
#: carries almost no atoms. A scan over a near-empty collection would report
#: every claim resolved by never reading one.
REASON_FLOOR = 100

#: A MINIMUM on the live anchored population, and the one number here that is a
#: ratchet rather than a shape check. R2339 raised it from 1 to 6 by anchoring
#: `access-extauth-usrpwd`'s three residual clauses; R2340 to 9 by anchoring
#: `access-acl`'s two, which sit on the same seam -- one of them is the ACL
#: subject axis that the usrpwd atom's discarded username feeds; R2341 to 15 by
#: anchoring `session-extauth`'s three, the layer under both, where the pubkey
#: method's config and runtime surfaces had never been anchored at all; R2342
#: to 19 on `router-multicast-faces`, which also gave `@ REMOVED` its FIRST live
#: subject -- the file that atom cited for its whole first clause is gone from
#: the pinned tree while the capability it named simply moved.
#:
#: The floor counts `anchored` only, deliberately. `removed` and `absent` have
#: their own floors, and those ask whether the FORM has a subject at all; a
#: minimum on them would have been a number nobody could satisfy for the twelve
#: rounds `removed` sat at zero.
#:
#: Why a minimum can never produce a legitimate red, which is what makes this
#: safe where a shrinking budget would not be: corrections to an inventory
#: reason are APPENDED, never rewritten (the store's convention, and the reason
#: R2337 withdrew a clause by adding a sentence rather than deleting one). An
#: anchor once written therefore stays, so the count only ever grows. The only
#: way under this floor is a rewrite that DELETES anchors -- which is the thing
#: worth catching, because it is silent otherwise: without this, removing every
#: anchor R2339 added would take the total from 9 back to 4 with both existing
#: floors still satisfied and the gate still printing OK.
#:
#: It lives beside the live adjudication rather than in `check_floors` on
#: purpose. Those floors ask whether a FORM is used at all and are unit-tested
#: with synthetic counts; this asks a question about the real store, and mixing
#: the two would make the classifier's own tests depend on how much of the
#: track has been anchored so far.
ANCHORED_FLOOR = 19


class InputError(Exception):
    """The gate could not READ its input. rc 2 -- not a verdict about claims."""


def claim_patterns(roots: tuple[str, ...]) -> tuple[re.Pattern, re.Pattern, re.Pattern]:
    """The three anchored forms, built over a caller-supplied root list.

    Parameterised so the selftest can drive a synthetic upstream: see the
    R2241 note in the module doc for why no real root may be written here.

    The `@ REMOVED` pattern is deliberately permissive about the root, matching
    the anchor gate's own reasoning -- a path named as ABSENT frequently has no
    root left to resolve against, and the marker itself declares that the token
    is a citation, so there is nothing to infer.
    """
    path = rf"(?:{'|'.join(roots)})/[\w/.-]+\.rs"
    sep = r"(?:\s*(?://[/!]?|#!?|\*)?\s*)"
    return (
        re.compile(rf"`({path})`{sep}@\s*`([^`\n]{{1,200}})`"),
        re.compile(rf"`((?:[\w.-]+/)+[\w.-]+\.rs)`{sep}@\s*REMOVED\b"),
        re.compile(rf"`({path})`{sep}@\s*ABSENT\s*`([^`\n]{{1,200}})`"),
    )


def store_reasons(store: pathlib.Path) -> dict[str, str]:
    """`{atom id: reason}` for every inventory entry that carries one.

    Parsed as JSON, from one named collection. `changelog_entries` is not
    filtered out here -- it is never read, which is a stronger guarantee than a
    filter, because a later edit cannot widen what was never opened.
    """
    try:
        doc = json.loads(store.read_text())
    except (OSError, ValueError) as exc:
        raise InputError(f"{STORE_REL} is not readable as JSON ({exc})") from exc
    entries = doc.get(INVENTORY_KEY)
    if not isinstance(entries, dict):
        raise InputError(
            f"{STORE_REL} has no `{INVENTORY_KEY}` object -- the store shape "
            f"moved, so this run graded nothing and must not report green"
        )
    out = {
        atom: body[REASON_KEY]
        for atom, body in entries.items()
        if isinstance(body, dict) and isinstance(body.get(REASON_KEY), str)
    }
    if len(out) < REASON_FLOOR:
        raise InputError(
            f"{STORE_REL} yielded {len(out)} inventory reason(s), under the "
            f"floor of {REASON_FLOOR}. A verdict about every atom's upstream "
            f"claims, issued by a run that read almost no atoms, is not a "
            f"verdict"
        )
    return out


def upstream_texts(root: pathlib.Path) -> dict[str, str]:
    """Every `.rs` file of the pinned checkout, keyed by relative path."""
    texts: dict[str, str] = {}
    for path in root.rglob("*.rs"):
        rel = path.relative_to(root)
        # R2338 — RELATIVE, for the reason the sibling gate records at the same
        # line: hosted CI puts the pinned checkout under a directory named
        # `target`, so testing the absolute path skips every file and the floor
        # below reports "this tree is empty" about a tree that is complete. This
        # gate inherited the shape from that one and would have been red hosted
        # the moment the layer reached it.
        if "target" in rel.parts:
            continue
        try:
            texts[rel.as_posix()] = path.read_text(errors="replace")
        except OSError as exc:
            raise InputError(f"{path} is not readable ({exc})") from exc
    if len(texts) < anchor.__dict__.get("UPSTREAM_FILE_FLOOR", 200):
        raise InputError(
            f"{root} yielded {len(texts)} Rust file(s), under the floor. A scan "
            f"over a near-empty tree would call every needle absent, which is a "
            f"verdict about zenoh issued by a run that never read zenoh"
        )
    return texts


def adjudicate(
    reasons: dict[str, str],
    texts: dict[str, str],
    roots: tuple[str, ...],
) -> tuple[list[str], dict[str, int]]:
    """Grade every anchored claim. Returns `(failures, counts)`.

    Each form is checked in the direction that can falsify it, and each one can
    fail for the OPPOSITE reason to its neighbour -- which is what stops any of
    them being a cheaper way to state a claim than the truth.
    """
    anchored_re, removed_re, absent_re = claim_patterns(roots)
    failures: list[str] = []
    counts = {"anchored": 0, "removed": 0, "absent": 0}

    for atom, reason in sorted(reasons.items()):
        for path, needle in anchored_re.findall(reason):
            counts["anchored"] += 1
            body = texts.get(path)
            if body is None:
                failures.append(
                    f"{atom}: `{path}` @ `{needle}` -- the pin has no such file, "
                    f"so this claim resolves against nothing"
                )
            elif needle not in body:
                failures.append(
                    f"{atom}: `{path}` @ `{needle}` -- the file is there and the "
                    f"needle is NOT in it. Either upstream dropped it (the claim "
                    f"needs `@ ABSENT`, or withdrawing) or the needle is wrong"
                )
        for path in removed_re.findall(reason):
            counts["removed"] += 1
            hits = [p for p in texts if p == path or p.endswith("/" + path)]
            if hits:
                failures.append(
                    f"{atom}: `{path}` @ REMOVED -- the pin HAS it ({hits[0]}). "
                    f"The sentence asserting its absence has become false"
                )
        for path, needle in absent_re.findall(reason):
            counts["absent"] += 1
            body = texts.get(path)
            if body is None:
                failures.append(
                    f"{atom}: `{path}` @ ABSENT `{needle}` -- the pin has no such "
                    f"file, so the claim is about nothing. Use `@ REMOVED`, which "
                    f"is the form for a path that is gone"
                )
            elif needle in body:
                failures.append(
                    f"{atom}: `{path}` @ ABSENT `{needle}` -- the needle is BACK. "
                    f"Upstream carries it again, so a residual withdrawn because "
                    f"upstream dropped it is live once more"
                )
    return failures, counts


def check_floors(counts: dict[str, int]) -> list[str]:
    """The two verdict-side floors. `reasons == 0` is an InputError, not here:
    an unreadable store is rc 2, an unused form is rc 1."""
    out: list[str] = []
    if sum(counts.values()) == 0:
        out.append(
            "no anchored upstream claim in any inventory reason. This gate has "
            "no subject -- every residual states its upstream evidence in a form "
            "nothing can grade, which is the condition it was built to end"
        )
    if counts["absent"] == 0:
        out.append(
            "no `@ ABSENT` claim in any inventory reason. That is the arm this "
            "gate exists for -- the case where upstream keeps the file and drops "
            "the thing -- and with a population of zero it grades nothing. "
            "Removing the last one is removing the discriminator"
        )
    return out


def check_ratchet(counts: dict[str, int]) -> list[str]:
    """The live-store ratchet. See `ANCHORED_FLOOR` for why a minimum is safe."""
    if counts["anchored"] < ANCHORED_FLOOR:
        return [
            f"{counts['anchored']} anchored claim(s), under the floor of "
            f"{ANCHORED_FLOOR}. Corrections to a reason are APPENDED, so this "
            f"count only grows on its own -- a drop means a rewrite deleted "
            f"anchors, and the residuals they pinned are ungraded again. "
            f"Restore them; do not lower this number to match"
        ]
    return []


def selftest() -> int:
    """Drive all three forms in BOTH directions over a synthetic upstream.

    No checkout and no store, so this runs on Layer C0 and proves the
    discrimination is real rather than proving a path exists. The root is
    SYNTHETIC and names no real upstream directory -- see the R2241 note.
    """
    roots = ("synthupstream",)
    texts = {
        "synthupstream/src/kept.rs": "fn alive() { let carried = 1; }",
        "synthupstream/src/other.rs": "fn unrelated() {}",
    }
    live = "synthupstream/src/kept.rs"
    gone = "synthupstream/src/deleted.rs"
    reasons = {f"pad-{i}": "no claim here" for i in range(REASON_FLOOR)}
    failed = 0

    def case(label: str, reason: str, want_fail: bool) -> None:
        nonlocal failed
        probe = dict(reasons)
        probe["subject"] = reason
        bad, _ = adjudicate(probe, texts, roots)
        if bool(bad) != want_fail:
            failed += 1
            print(
                f"  store-reasons selftest FAIL: {label} -- expected "
                f"{'a failure' if want_fail else 'no failure'}, got {bad}"
            )

    # The anchored form, both ways.
    case("anchor resolves", f"`{live}` @ `carried`", False)
    case("anchor needle gone", f"`{live}` @ `vanished`", True)
    case("anchor path gone", f"`{gone}` @ `carried`", True)
    # `@ REMOVED`, both ways.
    case("removed holds", f"`{gone}` @ REMOVED", False)
    case("removed but present", f"`{live}` @ REMOVED", True)
    # `@ ABSENT`, both ways -- the form this gate adds.
    case("absent holds", f"`{live}` @ ABSENT `vanished`", False)
    case("absent but present", f"`{live}` @ ABSENT `carried`", True)
    case("absent on a gone path", f"`{gone}` @ ABSENT `carried`", True)
    # The separator must cross a comment leader, the way the anchor gate's does.
    case("anchor across lines", f"`{live}`\n/// @ `carried`", False)

    # The floors, EMPTIED ONE AT A TIME -- a floor only tested alongside another
    # cannot be shown to fire by itself.
    for label, counts, want in (
        ("all forms empty", {"anchored": 0, "removed": 0, "absent": 0}, 2),
        ("only ABSENT empty", {"anchored": 3, "removed": 1, "absent": 0}, 1),
        ("ABSENT alone is enough", {"anchored": 0, "removed": 0, "absent": 1}, 0),
        ("populated", {"anchored": 1, "removed": 1, "absent": 1}, 0),
    ):
        got = len(check_floors(counts))
        if got != want:
            failed += 1
            print(
                f"  store-reasons selftest FAIL: floor '{label}' raised {got} "
                f"complaint(s), expected {want}"
            )

    # The ratchet, driven on its own and in both directions. Expressed against
    # the constant rather than a literal, so it keeps testing the boundary when
    # a later round raises the floor.
    for label, anchored, want in (
        ("exactly on the floor", ANCHORED_FLOOR, 0),
        ("one above the floor", ANCHORED_FLOOR + 1, 0),
        ("one below the floor", ANCHORED_FLOOR - 1, 1),
        ("anchors all deleted", 0, 1),
    ):
        got = len(check_ratchet({"anchored": anchored, "removed": 9, "absent": 9}))
        if got != want:
            failed += 1
            print(
                f"  store-reasons selftest FAIL: ratchet '{label}' raised {got} "
                f"complaint(s), expected {want}"
            )
    # The ratchet must be able to fail at all -- a floor of zero never fires.
    if ANCHORED_FLOOR <= 0:
        failed += 1
        print("  store-reasons selftest FAIL: ANCHORED_FLOOR cannot fire")

    # The store floor is an InputError, not a verdict.
    try:
        store_reasons(pathlib.Path("/nonexistent/store.json"))
    except InputError:
        pass
    else:
        failed += 1
        print("  store-reasons selftest FAIL: a missing store did not raise")

    if failed:
        print(f"  store-reasons selftest: {failed} case(s) FAILED")
        return 1
    print(
        "  store-reasons selftest OK -- three forms driven in both directions "
        "over a synthetic upstream, each floor emptied on its own, and the "
        "anchored ratchet driven either side of its boundary"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()

    try:
        reasons = store_reasons(ROOT / STORE_REL)
        root = anchor.upstream_root()
        if root is None:
            raise InputError(
                "no zenoh SOURCE checkout at the pinned version is reachable, "
                "so no claim could be adjudicated. Provision one "
                "(bash scripts/build-zenohd.sh) or point ZENOHD_SRC at a "
                "checkout of the pinned tag"
            )
        texts = upstream_texts(root)
    except InputError as exc:
        print(f"  store-reasons: INPUT -- {exc}")
        return 2

    failures, counts = adjudicate(reasons, texts, anchor.UPSTREAM_ROOTS)
    floors = check_floors(counts) + check_ratchet(counts)
    total = sum(counts.values())
    print(
        f"  store-reasons: {total} anchored upstream claim(s) across "
        f"{len(reasons)} inventory reason(s) -- {counts['anchored']} anchored, "
        f"{counts['removed']} @ REMOVED, {counts['absent']} @ ABSENT; "
        f"graded against {len(texts)} pinned file(s)"
    )
    for line in floors + failures:
        print(f"  store-reasons: {line}")
    return 1 if (failures or floors) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
