#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y605 — the dissect FEATURE census: the codec space vs the set `dissect` selects.

## Why this exists

The `dissect` feature's own doc says it "selects the whole codec-* MID space on
purpose: an observer reads every message it sees". That sentence is a
specification and the feature list is the implementation, and NOTHING COMPARED
THEM. The claim has now been wrong three times:

    R311y585  codec-scout / codec-hello missing   -- found by hand, writing a walker
    R311y597  codec-linkstate missing             -- found by hand, writing a walker
    R311y605  codec-join / codec-fragment /
              codec-keep-alive missing            -- found by THIS census

Each discovery was accidental, and the sibling gate that exists
(`dissect::tests::the_dissector_and_the_decoder_recognise_the_same_mid_set`)
structurally cannot see any of them: it walks the 32 NETWORK MIDs, and all
three gaps live elsewhere -- scout / hello on the disjoint scouting MID space,
linkstate inside an OAM *body*, and join / fragment / keep-alive on the
TRANSPORT MID space.

So the gate has to be over the feature space itself, which is the one place
every carrier appears exactly once.

## What a missing feature actually costs

Not "the walker disappears" -- the walkers are hand-written against `wire_const`
and stay compiled. What disappears is the CODEC that would independently
confirm them. `dissect`'s agreement tests decode the same bytes through the
generated codec and reject any disagreement, so a MID whose codec is not in the
build has a walker judged only against the fixture author's reading of the
layout -- which is the thing under test. R311y605's `Join` arm was ten
hand-walked fields with no oracle and no test at all.

## Why a census and not a hardcoded list

Same reason as `dissect_name_census.py`: a list decays. This reads BOTH sides
out of the manifests, so a new `codec-*` feature in `wz-codecs` reds the gate
until someone decides -- select it, or declare why not. Rule 3 (no stale
excuse) is what stops the exclusion table from becoming the thing it was meant
to prevent.

## What it does NOT check

That the selected codec is actually USED as an oracle. Selecting a feature
makes an agreement test possible; writing one is the walker author's job, and
`dissect`'s own tests are where that is asserted.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CODECS_MANIFEST = ROOT / "crates" / "wz-codecs" / "Cargo.toml"
SESSION_MANIFEST = ROOT / "crates" / "wz-session-core" / "Cargo.toml"

# The surface under census: the feature whose doc makes the "reads every message
# it sees" claim.
SURFACE = "dissect"

# EXCLUDED: codec-* features `dissect` deliberately does NOT select, each with
# the reason. Rule 3 makes every entry here perishable -- select the feature and
# this entry must go, delete the feature and this entry must go.
EXCLUDED = {
    "codec-serial": (
        "LINK framing, not a zenoh message: the COBS + CRC32 envelope zenoh-pico "
        "wraps its serial link in. It carries no MID and sits outside the "
        "dissector's transport / network / zenoh / scouting spaces by design -- the "
        "same ground on which dissect_name_census.py carries `crc32` as awaiting no "
        "walker. A serial capture would also need a link type to arrive through, and "
        "there is no standard DLT for one"
    ),
}


def exposed_codec_features(manifest: Path) -> set[str]:
    """Every `codec-*` feature `wz-codecs` declares."""
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    return {name for name in data.get("features", {}) if name.startswith("codec-")}


def selected_codec_features(manifest: Path, root_feature: str) -> tuple[set[str], list[str]]:
    """The `codec-*` features `root_feature` selects, transitively.

    Two forms reach `wz-codecs`: this crate's own `codec-X` forwarder, and a
    direct `wz-codecs/codec-X`. Both are followed, because writing either one is
    how the list has actually been maintained -- `dissect` mixes them.

    Returns the resolved set plus any `wz-codecs/codec-X` name that this crate
    routes through a forwarder of a DIFFERENT name, which would make the two
    sides disagree silently.
    """
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    features: dict[str, list[str]] = data.get("features", {})
    if root_feature not in features:
        raise KeyError(f"{manifest} has no `{root_feature}` feature")

    resolved: set[str] = set()
    mismatched: list[str] = []
    seen: set[str] = set()
    pending = [root_feature]
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        for entry in features.get(name, []):
            # `dep:foo` and `foo?/bar` are dependency activations, not features
            # of this crate; only the wz-codecs ones matter here.
            if entry.startswith("wz-codecs/") or entry.startswith("wz-codecs?/"):
                sub = entry.split("/", 1)[1]
                if sub.startswith("codec-"):
                    resolved.add(sub)
                continue
            if entry.startswith("dep:"):
                continue
            if "/" in entry:
                continue
            if entry.startswith("codec-"):
                # A forwarder. Verify it forwards to its own name: a
                # `codec-join = ["wz-codecs/codec-frame"]` typo would otherwise
                # satisfy this census while selecting the wrong codec.
                forwarded = {
                    e.split("/", 1)[1]
                    for e in features.get(entry, [])
                    if e.startswith(("wz-codecs/", "wz-codecs?/"))
                }
                if entry not in forwarded:
                    mismatched.append(
                        f"{entry!r} forwards to {sorted(forwarded) or 'nothing'}, "
                        f"not to 'wz-codecs/{entry}'"
                    )
                resolved.update(f for f in forwarded if f.startswith("codec-"))
            pending.append(entry)
    return resolved, mismatched


def main() -> int:
    for path in (CODECS_MANIFEST, SESSION_MANIFEST):
        if not path.is_file():
            print(f"dissect-feature-census: cannot read {path}", file=sys.stderr)
            return 1

    exposed = exposed_codec_features(CODECS_MANIFEST)
    if not exposed:
        # A version that found nothing would exit 0 forever and read as
        # coverage. Same rule as count_guard_lint.py's empty-scope failure.
        print(
            "dissect-feature-census: found NO codec-* feature in "
            f"{CODECS_MANIFEST} -- the parse is broken, not the manifest",
            file=sys.stderr,
        )
        return 1
    try:
        selected, mismatched = selected_codec_features(SESSION_MANIFEST, SURFACE)
    except KeyError as e:
        print(f"dissect-feature-census: {e}", file=sys.stderr)
        return 1

    failures: list[str] = list(mismatched)

    # Invariant 1: no silently unselected codec.
    for name in sorted(exposed - selected - set(EXCLUDED)):
        failures.append(
            f"wz-codecs exposes {name!r} and `{SURFACE}` neither selects it nor "
            "declares why not. A dissector missing a codec still WALKS that MID "
            "(the walkers are hand-written) but has no independent decoder to be "
            "judged against -- add it to the feature list, or to EXCLUDED with "
            "the reason it is outside the dissector's message space"
        )

    # Invariant 2: no stale excuse.
    for name in sorted(set(EXCLUDED) & selected):
        failures.append(
            f"{name!r} is declared EXCLUDED but `{SURFACE}` selects it -- "
            "delete the EXCLUDED entry"
        )

    # Invariant 3: no stale declaration.
    for name in sorted(set(EXCLUDED) - exposed):
        failures.append(
            f"{name!r} is declared EXCLUDED but wz-codecs no longer exposes it -- "
            "delete the EXCLUDED entry"
        )

    # Invariant 4: nothing selected that does not exist.
    for name in sorted(selected - exposed):
        failures.append(
            f"`{SURFACE}` selects {name!r}, which wz-codecs does not expose"
        )

    print(
        f"dissect-feature-census: {len(exposed)} codec feature(s) exposed, "
        f"{len(selected & exposed)} selected by `{SURFACE}`, "
        f"{len(EXCLUDED)} declared outside its message space"
    )
    if failures:
        for line in failures:
            print(f"  FAIL {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
