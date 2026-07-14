#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y259 — enabled-feature closure: ask cargo, do not re-implement cargo.

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
    the atom's OWN feature name — it does NOT imply the code is always-on. session-extqos
    is reserved with 0 own cfg sites yet gated by 155 `transport-qos` sites, so it is
    elidable and the "compiled regardless" inference above is FALSE for it. It is not
    FOUNDATIONAL today (it is PARTIAL), so this exemption does not currently reach it —
    but the premise is narrower than the bullet's phrasing suggests.
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
    txt = RUN_CI.read_text()
    for m in re.finditer(r"cargo build -p wz-ap-demo[^\n|)]*?--features ([A-Za-z0-9_,-]+)", txt):
        feats.update(m.group(1).split(","))
    return tuple(sorted(feats))


def binary_closure(binary: str) -> frozenset[str]:
    """Closure for a binary a corpus test drives, by the harness helper it calls."""
    if binary == "wz-ap-demo":
        return closure("wz-ap-demo", ap_demo_lane_features())
    return closure(binary)


if __name__ == "__main__":
    pkg = sys.argv[1] if len(sys.argv) > 1 else "wz-e2e-pubsub"
    feats = sorted(binary_closure(pkg))
    print("%s: %d wz features" % (pkg, len(feats)))
    print(" ".join(feats))
