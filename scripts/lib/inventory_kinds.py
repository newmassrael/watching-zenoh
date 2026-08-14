#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y743 (N48) — what KIND each inventory entry is: one definition, every consumer.

## The duplication this removes, and the defect it already caused

`mnemosyne-cli query --list-inventory` returns ENTRIES, and the store's entries
are not all the same kind of thing. Today it holds 213 atoms and 6 `preset-*`
bundles, and every consumer that wants "the atoms" has been drawing that line
BY HAND:

    apfull_membership.py   Layer A5   filters `preset-`
    audit-catalog-status.sh Layer A3  filters `preset-` ("bundles, not atoms")
    domain_census.py        census    filters `preset-`
    crossimpl_audit.py      Layer A4  consumes the same list

Four copies of one predicate is the shape this workspace already knows the
price of — `crossimpl_corpus.py` (R311y259) exists because Layer C0 and Layer
A4 had drifted into two spellings of one question. And the inventory version
of that drift has ALREADY been paid once: `domain_census.py` records that
conflating the two kinds is how R311y315's banner "reported the store as having
219 atoms when it has 213".

This module is that predicate, once.

## Why it grows a THIRD kind now

R311y743 begins moving the open-debt register into the store, because the two
debt axes in this project have opposite drift histories and the difference is
the mechanism, not the content: the 213 atoms are typed inventory entries bound
to sections and re-derived by four gates, and four independent re-measurements
(R311y708 / y727 / y739 / y740) produced identical numbers; the §F base list and
the carry list live as prose outside the store, and R311y739 could re-establish
the open/closed state of four of roughly two hundred.

Debt entries are registered under a `debt-` prefix, exactly as bundles use
`preset-`. That is deliberately the SAME mechanism rather than a new one: the
namespace was already heterogeneous, so this is not a category being introduced,
it is a category being named. What would have been a category error is adding
the third kind while leaving the predicate copied in four places — a later
consumer that forgot the filter would silently count debt items as atoms, which
is R311y315 again with a bigger denominator.
"""

from __future__ import annotations

import json
import re
import subprocess

PRESET_PREFIX = "preset-"
DEBT_PREFIX = "debt-"

# The TAG slot of an inventory `reason` is its HEAD token and nothing else.
#
# R311y800 — this is here because the fourth consumer got it wrong in the one way
# the other three did not. `apfull_membership.py`'s `unbuilt` predicate was
# `"UNBUILT" in reason.upper()` — a substring search over a reason that runs to
# thousands of words — while `crossimpl_audit.py` and `audit-catalog-status.sh`
# both already read the head. R311y799 wrote the sentence "as mis-mechanised
# rather than merely unbuilt" into `session-matching`'s reason, retracting a
# residual, and Layer A5 read that retraction as a tag: it declared a member the
# preset counts as covered to be UNBUILT and redded the hosted run
# (31762809988). Nothing about the atom had changed; the gate read prose.
#
# The head IS the tag by the store's own convention, established here by direct
# read of the store as it stood at 5a67b235^, when the tag had live users:
#
#     api-compat-c        "UNBUILT: (R311y256: the out-of-scope label is ...)"
#     runtime-tokio-uring "UNBUILT: F=io_uring fixed-buf adapter; P=..."
#
# and `api-compat-c`'s own body went on to say "genuinely unbuilt work that
# belongs on the schedule" — so the distinction between a tag and a word was
# already load-bearing in the very entries the tag was invented for.
#
# The word-boundary form rather than the `split(":")[0].split("(")[0]` spelling
# the two working consumers carry: MEASURED across all 301 entries, the two
# disagree on 0 of the 219 atoms, and differ only on `debt-` heads ("CLOSED
# R311Y725" -> "CLOSED") and `preset-` heads, which no tag consumer reads. So
# adopting it is a no-op for every consumer today and is the form that survives
# a reason whose head is followed by prose instead of a delimiter.
_HEAD_TAG_RE = re.compile(r"\s*([A-Za-z][A-Za-z0-9-]*)")


def load_entries() -> list[dict]:
    """Every inventory entry, unfiltered. Raises if the CLI is unavailable."""
    out = subprocess.run(
        ["mnemosyne-cli", "query", "--list-inventory", "--json"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    data = json.loads(out)
    return data if isinstance(data, list) else data.get("entries", data.get("inventory", []))


def entry_id(entry: dict) -> str | None:
    return entry.get("id") or entry.get("inventory_id")


def reason_head_tag(reason: str | None) -> str | None:
    """The tag an inventory `reason` carries: its HEAD token, upper-cased.

    `None` for an empty or untagged reason. A tag is a slot, not a word that
    occurs somewhere — a reason is free prose after the head and routinely
    discusses the very tags it does not carry. Every consumer that wants to know
    "what does the inventory call this atom" asks HERE; see `_HEAD_TAG_RE` for
    the round that paid for the fourth spelling of the question.
    """
    m = _HEAD_TAG_RE.match(reason or "")
    return m.group(1).upper() if m else None


def is_preset(eid: str) -> bool:
    return eid.startswith(PRESET_PREFIX)


def is_debt(eid: str) -> bool:
    return eid.startswith(DEBT_PREFIX)


def is_atom(eid: str) -> bool:
    """An ATOM is an entry that is neither a preset bundle nor a debt item.

    Defined by exclusion on purpose. The alternative — an `atom-` prefix — would
    mean renaming 213 live ids that section_refs, cargo features and four gates
    all already spell without one, and a rename is how a stable axis stops being
    stable.
    """
    return not is_preset(eid) and not is_debt(eid)


def atoms(entries: list[dict] | None = None) -> dict[str, dict]:
    """`{id: entry}` for the atom kind only — the denominator A3 / A5 report."""
    if entries is None:
        entries = load_entries()
    out = {}
    for e in entries:
        eid = entry_id(e)
        if eid and is_atom(eid):
            out[eid] = e
    return out


def debt(entries: list[dict] | None = None) -> dict[str, dict]:
    """`{id: entry}` for registered debt items only."""
    if entries is None:
        entries = load_entries()
    out = {}
    for e in entries:
        eid = entry_id(e)
        if eid and is_debt(eid):
            out[eid] = e
    return out


def _main() -> int:
    """`--atoms` / `--debt` emit the filtered entry list as JSON, for the SHELL
    consumers (Layers A3 and A4 are bash) so they share this predicate rather
    than re-spelling it in their own inline python."""
    import sys

    entries = load_entries()
    if len(sys.argv) == 2 and sys.argv[1] == "--atoms":
        keep = atoms(entries)
    elif len(sys.argv) == 2 and sys.argv[1] == "--debt":
        keep = debt(entries)
    else:
        print("usage: inventory_kinds.py --atoms|--debt", file=sys.stderr)
        return 2
    json.dump([e for e in entries if entry_id(e) in keep], sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
