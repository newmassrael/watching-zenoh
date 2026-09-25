#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y259 (no register item) — enabled-feature closure: ask cargo, do not re-implement cargo.

This is the SECOND ARM of the cross-impl proof gate (Layer A4), and it is what makes
the axis derived rather than asserted.

A `wz-proves:` claim is authored prose: nothing stops a human from listing ten atoms
for a test that witnesses one. But an atom IS a cargo feature, and a feature that is
not enabled for the binary under test compiles to NOTHING in that binary. So:

    an atom that is not in the enabled-feature closure of the binary a test drives
    CANNOT POSSIBLY have been witnessed by that test.

That is a mechanical, compiler-grounded refutation — the same shape as Layer A3's
`active <=> >=1 cfg(feature) site` invariant, which works precisely because a cfg site
cannot lie about itself.

## What this arm does NOT catch (stated so nobody trusts it further than it goes)

It refutes; it never confirms. Three gaps are inherent:

  - **Compiled but unexercised.** An atom in the closure may simply never be on the path
    the test drives. Containment cannot see that; only reading the test can.
  - **Non-active atoms are exempt.** A FOUNDATIONAL atom has zero `cfg(feature=..)` sites
    (Layer A3 invariant #2), so its code is compiled whether or not the feature is
    enabled — "not in the closure" therefore does not mean "not in the binary", and the
    arm must not fire on it. (R311y300 removed a hardcoded "37 of the 160 denominator
    atoms" here: the live denominator was already 162 and nothing gated the number, so
    it rotted silently — the same defect class R311y299 found in audit-catalog-status.sh's
    own examples. Layer A4 PRINTS the live denominator every run; read it there.)
    CAVEAT, and it is load-bearing: "zero cfg sites" is invariant #2's guarantee about
    the atom's OWN feature name — it does NOT imply the code is always-on. A feature with
    no site of its own can still be elided by a feature that gates it, so the "compiled
    regardless" inference above is FALSE for such an atom. The exemption reaches only
    FOUNDATIONAL atoms, so it does not currently apply to a PARTIAL one either way — but
    the premise is narrower than the bullet's phrasing suggests.
    ⚠ R2659 — THIS CAVEAT NAMED `session-extqos` AS ITS EXAMPLE AND BOTH ITS NUMBERS HAVE
    ROTTED, which is the very defect the paragraph above describes, sitting one sentence
    below it. Re-measured against the tree: `session-extqos` now carries 65 cfg sites of
    its OWN (13 in wz-runtime-tokio, 34 in wz-session-core, 18 in wz-ap-demo, 0 in tests),
    not 0, and `transport-qos` carries 182, not 155. So it is no longer an example of
    "elidable with zero own sites" at all — it is elidable by its own name. The caveat's
    POINT stands and is stated above without an example rather than with a false one;
    a replacement example must be MEASURED, never assumed.
  - **In-process tests have a broad closure.** A test that drives no wz binary links the
    `wz-integration-tests` dev-dependency graph, which enables ~83 wz features. For those
    45 corpus files the arm can refute very little.

So containment kills the *impossible* claim, not the *unearned* one. The unearned one is
caught by reading the test, and by the adversarial review that produced this note.

## Why cargo answers this, and not a hand-rolled resolver

The first cut of this module re-implemented cargo's feature resolution (walking
`[features]` tables, `dep/feat` edges, `default-features = false`). It was wrong twice
in a row -- it reported `liveliness-token` and `query-get` as enabled for
`wz-e2e-pubsub`, whose whole purpose is to PIN a subset that excludes them. Cargo
itself says otherwise, and cargo is the thing that actually builds the binary. A gate
whose model of the build disagrees with the build is a gate that lies, so there is no
second model here: cargo resolves, we read.

## Why `-f '{p}|{f}'` and not the `feature "x"` edge nodes

`cargo tree -e features` prints feature EDGES, and it DEDUPES repeated subtrees --
`wz-ap-demo`'s tree carries 316 `(*)` collapse markers, so counting edge nodes silently
undercounts (it reported 11 features for a binary that really enables ~90). The `{f}`
format field instead prints each package's fully RESOLVED feature list, which survives
the dedupe because the first occurrence of a package carries it. Union those per-package
lists and you have the closure cargo will actually compile.

## Soundness direction (deliberate)

`wz-ap-demo` is built with different `--features` by different CI lanes, so its closure
is the UNION over every lane that builds it. A union is a SUPERSET of any single lane's
closure, so the invariant can never produce a FALSE FAILURE -- only a weaker true one.
The gate is a refutation tool: it proves a claim IMPOSSIBLE, never proves one correct.
Erring toward the superset keeps that asymmetry honest.
"""

from __future__ import annotations

import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CRATES_DIR = REPO_ROOT / "crates"
RUN_CI = REPO_ROOT / "scripts" / "run-ci.sh"

# Only the wz packages carry atoms; third-party features are noise.
WZ_ROW_RE = re.compile(r"^(wz[a-z0-9-]*) v[^|]*\|(.*)$")


@lru_cache(maxsize=None)
def closure(package: str, features: tuple[str, ...] = ()) -> frozenset[str]:
    """The set of wz feature names cargo enables when building `package`."""
    cmd = ["cargo", "tree", "-p", package, "-e", "features",
           "--prefix", "none", "-f", "{p}|{f}"]
    if features:
        cmd += ["--features", ",".join(features)]
    r = subprocess.run(cmd, cwd=CRATES_DIR, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("cargo tree failed for %s: %s" % (package, r.stderr.strip()))
    out: set[str] = set()
    for line in r.stdout.splitlines():
        m = WZ_ROW_RE.match(line.strip())
        if not m:
            continue
        out.update(f for f in m.group(2).split(",") if f)
    return frozenset(out)


@lru_cache(maxsize=None)
def ap_demo_lane_features() -> tuple[str, ...]:
    """Every `--features` set run-ci.sh builds wz-ap-demo with, unioned.

    Derived from run-ci.sh rather than hardcoded: a lane that starts building
    wz-ap-demo with a new feature must widen the closure automatically, or the
    containment invariant would start rejecting legitimate new claims.
    """
    feats: set[str] = set()
    # R2861 — through `cargo_builds`, the one reader of run-ci.sh's builds. The
    # regex this used could not see a `--features \` whose list sits on the
    # next line, which is how 19 of 51 demo builds are written: five features
    # (adminspace-write, pubsub-delete, router-config-mutate,
    # routing-interceptor-hotreload, routing-interest-pending-gc) never reached
    # this union.
    for offset, pkg, build_feats in cargo_builds(RUN_CI.read_text()):
        if pkg != "wz-ap-demo":
            continue
        # A shell-assembled list (`--features "$feats"`) names no feature this
        # reader can resolve; handing it to `cargo tree` would fail there with a
        # message about a feature called `$feats`. Refuse here, by position.
        unresolved = [f for f in build_feats if "$" in f]
        if unresolved:
            raise RuntimeError(
                "run-ci.sh offset %d builds wz-ap-demo with a shell-assembled "
                "feature list %s; the lane feature union cannot resolve it"
                % (offset, unresolved))
        feats.update(build_feats)
    return tuple(sorted(feats))


# R2861 — a `cargo build` invocation ends at the first shell operator. Stopping
# at `&`, `|`, `;` and `)` is what lets `cd crates && cargo build -p A ... &&
# cargo build -p B` read as TWO builds rather than one whose second `-p`
# overwrites the first.
_CARGO_BUILD = re.compile(r"cargo build\b[^\n;&|)]*")


def cargo_builds(text: str) -> list[tuple[int, str | None, tuple[str, ...]]]:
    """Every `cargo build` in `text` as `(offset, package, features)`.

    THE ONE READER of the builds a lane runs. Four gates used to each carry a
    regex of their own for this, and they disagreed in exactly the shapes
    run-ci.sh writes most: a `--features \\` continued onto the next line was
    invisible to three of them, and a build chained by `&&` to a second build
    was misattributed by the fourth.

    * Continuations are joined by replacing each backslash-newline with TWO
      spaces, so every offset is the offset in `text` itself and a caller can
      still turn one into a line number.
    * A build on a comment line is not a build.
    * `features` is `()` for a build that names none, which a caller must be
      able to tell apart from "no build at all" (an absent entry).
    * `/` stays in a feature: `wz/transport-stats` is a dependency's feature,
      which cargo accepts (R2845).
    """
    joined = text.replace("\\\n", "  ")
    out: list[tuple[int, str | None, tuple[str, ...]]] = []
    for m in _CARGO_BUILD.finditer(joined):
        line_start = text.rfind("\n", 0, m.start()) + 1
        if text[line_start:m.start()].lstrip().startswith("#"):
            continue
        toks = m.group(0).split()
        pkg: str | None = None
        feats: tuple[str, ...] = ()
        for j, tok in enumerate(toks):
            if tok in ("-p", "--package") and j + 1 < len(toks):
                pkg = toks[j + 1]
            elif tok == "--features" and j + 1 < len(toks):
                feats = tuple(f for f in toks[j + 1].strip("\"'").split(",") if f)
            elif tok.startswith("--features="):
                feats = tuple(f for f in tok.split("=", 1)[1].strip("\"'").split(",") if f)
        out.append((m.start(), pkg, feats))
    return out


def binary_closure(binary: str) -> frozenset[str]:
    """Closure for a binary a corpus test drives, by the harness helper it calls."""
    if binary == "wz-ap-demo":
        return closure("wz-ap-demo", ap_demo_lane_features())
    if binary == "wz-capi-pico":
        # The C-ABI cdylib (§5.27) is reached through the `wz` facade's
        # `api-compat-pico` feature, which is where the atom's ONLY cfg site
        # lives (`crates/wz/src/lib.rs`: `#[cfg(feature = "api-compat-pico")]
        # pub use wz_capi_pico as capi_pico`). Asking the wz-capi-pico package
        # for its own closure would answer the wrong question and refute a true
        # claim: the crate declares no feature by that name, because the feature
        # that pulls it in belongs to the facade above it. So the closure of the
        # artifact is the closure of the build that emits it.
        return closure("wz", ("api-compat-pico",))
    if binary == "wz-capi-c":
        # Same shape and same reason as its pico twin above: `api-compat-c`'s only
        # cfg site is the facade's (`crates/wz/src/lib.rs`), and the wz-capi-c
        # package declares no feature by that name. The two ABIs are mutually
        # exclusive (the facade `compile_error!`s on both), so this is a SECOND
        # single-feature build rather than a wider one — asking for both at once
        # would not compile, which is exactly why each artifact gets its own
        # closure here instead of one union.
        return closure("wz", ("api-compat-c",))
    return closure(binary)


if __name__ == "__main__":
    pkg = sys.argv[1] if len(sys.argv) > 1 else "wz-e2e-pubsub"
    feats = sorted(binary_closure(pkg))
    print("%s: %d wz features" % (pkg, len(feats)))
    print(" ".join(feats))
