#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y779 (no register item) — how many demo-spawning fixtures do NOT check that
the binary they spawn is newer than the tree they are testing.

## The defect this counts

`wz_ap_demo_binary()` returns whatever file exists at `crates/target/<profile>/`.
A fixture that spawns it is making a claim about the CURRENT tree; a binary built
before the change under test turns that into a claim about some past one, and the
failure mode is the worst kind -- it reads as "the feature does not work", so the
diagnosis goes hunting somewhere else.

That is not hypothetical. R311y774 wrote a witness for R311y771's Interest emit,
ran it against a demo predating that emit, and attributed the red to a
feature-closure defect that did not exist; R311y776 retracted the whole diagnosis.
The binary prints its feature banner either way, so nothing in the output
discriminates. `assert_demo_binary_newer_than_sources` is the check.

## Why a COUNT and not a blanket requirement

Not every spawning fixture needs it. Layer E4's negative twin spawns the demo only
to prove it REJECTS `--router` with exit 2 -- staleness cannot mislead an argv
check, and requiring the call there would be cargo-culting. The distinction is not
mechanically available, so a gate that demanded the call everywhere would force 110
edits, most of them wrong.

So this counts instead, bidirectionally, exactly as the Layer C1bz doc budget does:

  * a NEW spawning fixture with no freshness check RAISES the number -> red, and
    the author must either add the call or say why this one cannot be misled;
  * FIXING one LOWERS it -> also red, until the smaller number is written down in
    the same commit. A stale budget is a gate that has quietly stopped measuring.

The number is therefore a standing, honest statement of how much of the corpus can
still be fooled -- not a claim that the problem is solved.

## The population comes from the corpus SSOT, not a grep

`crossimpl_corpus.scan_all()` already resolves which fixtures drive which wz
binary, transitively through `common::*` wrapper helpers. A grep for
`wz_ap_demo_binary(` would miss every fixture that reaches the demo through a
wrapper -- the same hole that module was built to close for Layer C0 and A4.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import crossimpl_corpus as corpus  # noqa: E402

# The binary whose staleness has actually cost a wrong diagnosis. The other wz
# e2e binaries (`wz-e2e-*`) have the same hole and are deliberately NOT counted
# here: none of them has been observed to mislead, and folding them in would mix
# a measured problem with an assumed one. Widening the scope is its own round.
WATCHED_BINARY = "wz-ap-demo"

FRESHNESS_CALL = "assert_demo_binary_newer_than_sources"

# MEASURED at R311y779: 113 fixtures drive wz-ap-demo, 3 assert freshness.
#
# The three that do are the zenohd-adjudicated witnesses added R311y774-y778,
# which is not a coincidence -- they are the ones whose red was actually
# misdiagnosed, so they are where the check was written.
#
# R311y839 raises it to 111 for `close_scope_zenohd_witness.rs`, and this is the
# "say why this one cannot be misled" branch rather than a missing edit. That
# fixture asserts nothing about wz: it reads two bytes a real zenohd wrote and
# checks the scope flag in them. The demo enters only INSIDE
# `spawn_zenohd_on_ephemeral_tcp`, whose handshake probe is how the helper knows
# zenohd is past TCP-accept -- so a stale demo can make the probe fail to detect
# readiness, which surfaces as a connect or read error on the next line, never as
# a wrong verdict about zenohd's byte. Adding the call would make a foreign-oracle
# measurement depend on the freshness of a wz artifact it never inspects.
# R311y840 LOWERS it to 110, the downward arm this gate exists to catch.
# `wz_router_routes_pico_interop.rs` gained the call, and it gained it in the
# shared `spawn_wz_router` helper rather than per test, so ONE edit covers the
# file's five fixtures. The net is -1 even though the same commit ADDS two of
# those five, which is the arithmetic worth writing down: a per-file count moves
# by the file, not by the fixture.
#
# It is the right file to fix rather than an arbitrary one. Its two new legs
# assert a code path a demo built before this round DOES NOT HAVE (the router's
# query plane), so a stale binary there does not merely weaken the proof — it
# reproduces exactly the red the legs are written to detect, and the diagnosis
# goes hunting in the routing kernel for a defect that is in the build.
MISSING_FRESHNESS = 110


def main() -> int:
    files = corpus.scan_all()
    spawning = [f for f in files if WATCHED_BINARY in f.binaries]
    missing = [f for f in spawning if FRESHNESS_CALL not in Path(f.path).read_text()]
    measured = len(missing)

    if measured == MISSING_FRESHNESS:
        print(
            f"binary-freshness lint: {len(spawning)} fixture(s) spawn {WATCHED_BINARY}, "
            f"{len(spawning) - measured} assert freshness, {measured} carried "
            f"(a stale binary there reads as a broken feature)"
        )
        return 0

    print(
        f"  binary-freshness FAIL: {measured} fixture(s) spawn {WATCHED_BINARY} without "
        f"{FRESHNESS_CALL}, carried number says {MISSING_FRESHNESS}",
        file=sys.stderr,
    )
    if measured > MISSING_FRESHNESS:
        print(
            "  A new spawning fixture arrived without the check. Add\n"
            f"    {FRESHNESS_CALL}(&demo);\n"
            "  right after the binary is resolved -- or, if this fixture only reads the\n"
            "  path (usage text, argv rejection) and staleness cannot mislead it, raise\n"
            "  the carried number in this file and say which fixture and why.",
            file=sys.stderr,
        )
    else:
        print(
            "  A fixture gained the check -- good. Lower the carried number in this file\n"
            "  in the SAME commit, or the gate quietly stops measuring (the drift catch\n"
            "  Layer C1bz's doc budget applies for the same reason).",
            file=sys.stderr,
        )
    for f in sorted(missing, key=lambda x: str(x.path))[:5]:
        print(f"    - {f.path}", file=sys.stderr)
    if len(missing) > 5:
        print(f"    ... and {len(missing) - 5} more", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
