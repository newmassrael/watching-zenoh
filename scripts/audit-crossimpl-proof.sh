#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# audit-crossimpl-proof.sh — the CROSS-IMPL PROOF axis (Layer A4).
#
# Motivation:
#   Layer A3 joined two worlds that nothing else joined: the Mnemosyne catalog and
#   the cargo/cfg reality. It can now answer "is there a knob?" (status) and, since
#   R311y257, "is it built?" (the implementation tag). It cannot answer the question
#   the north star actually turns on:
#
#       is this atom PROVEN against a real foreign implementation?
#
#   "zenoh + zenoh-pico FULL" is not reached by building 212 atoms; it is reached by
#   witnessing them interoperate with the real zenoh-pico C stack and the real
#   zenoh-full router. That number existed only as a hand estimate ("~75% foreign-
#   proven") in a memory file whose own text says it was never recomputed, and whose
#   cited authority ([[project-pico-parity-status]]) does not exist in this repo. It
#   could not be recomputed without grepping English. Same defect class R311y257 fixed
#   for the implementation axis; this gate is the fix for the proof axis.
#
# Why the claim lives in the test and not in the inventory:
#   A proof claim's truth lives in the corpus, not in prose. The Mnemosyne inventory
#   schema is closed (5 fields; no new field -- anti-patterns #9), and a declared
#   "proven" flag in `reason` would be exactly the metadata-vs-code lie A3's own
#   docstring says no functional test can catch. So the claim is authored next to the
#   #[test] that does the proving, and this gate joins it to the catalog.
#
# The two arms (this is what makes the axis DERIVED, not asserted):
#   ARM 1 (corpus)     — WHICH tests can witness a foreign impl is derived from code,
#                        by resolving the harness call graph (scripts/lib/crossimpl_corpus.py).
#                        A wz<->wz test cannot claim foreign proof.
#   ARM 2 (containment)— WHETHER a claimed atom could possibly have been witnessed is
#                        derived from cargo: an atom that is not in the enabled-feature
#                        closure of the binary under test compiles to NOTHING in it, so
#                        it cannot have been proven by it (scripts/lib/feature_closure.py).
#                        This kills the "list ten, witness one" over-claim class.
#   Only the atom<->test LINK is authored. Everything that can be derived, is.
#
# Invariants (hard FAIL):
#   A4-1 name integrity      every claimed atom exists in the inventory.
#   A4-2 numerator subset    every claimed atom is in the DENOMINATOR (built and
#                            foreign-observable). Without this the ratio is not even
#                            well-formed -- an UNBUILT atom could be claimed proven.
#   A4-3 no false foreignness a claim may appear only in a corpus-derived file.
#   A4-4 no silent contribution every corpus #[test] declares: either it names atoms,
#                            or it says `none -- <reason>`. A new interop test that
#                            declares nothing would silently under-report the number.
#   A4-5 containment         every claimed atom is in the feature closure of the binary
#                            that test drives.
#   A4-6 contradiction gate  no atom in the foreign-NON-observable set may be claimed.
#                            This is what makes that exclusion FALSIFIABLE rather than
#                            asserted: witness one, and the gate fails and the exclusion
#                            was wrong.
#   A4-7 kind agrees with class  a `wz->zenohd` claim may only come from a file that
#                            actually spawns zenohd, etc.
#
# The roll-up is a REPORT, not a gate (A3 does the same: hard fails + a roll-up).
#
# NO PERCENTAGE IS PRINTED, deliberately.
#   R311jl already ruled the wz-catalog denominator invalid for parity claims
#   ("it includes non-pico MS3+ atoms ... it is NOT the zenoh-pico parity number"),
#   and its honest shape was three numbers against three NAMED denominators. A single
#   X% would be quoted as "we are at X%" the moment it exists, and would invite
#   comparison with the legacy ~75% pico-parity figure -- a category error. Counts
#   against a named denominator, plus the actionable unproven list, is the honest shape.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v mnemosyne-cli >/dev/null 2>&1; then
    echo "audit-crossimpl-proof SKIP (mnemosyne-cli not on PATH)"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "audit-crossimpl-proof SKIP (python3 not on PATH)"
    exit 0
fi

INV_FILE="$(mktemp)"
trap 'rm -f "$INV_FILE"' EXIT
mnemosyne-cli query --list-inventory --json 2>/dev/null >"$INV_FILE"

INV_FILE="$INV_FILE" python3 "$SCRIPT_DIR/lib/crossimpl_audit.py"
