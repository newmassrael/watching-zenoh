#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# audit-catalog-status.sh — repo-side gate asserting that every
# Mnemosyne feature-catalog atom's `status` agrees with the actual
# cargo-feature gate reality in the source tree.
#
# Motivation:
#   The composability CI triad (build C1h/C4b/C4c, behaviour C1c-g/C1j,
#   clippy C2/C3/C4d, footprint Layer F) validates the *cargo features*
#   themselves — they build, behave, lint, and elide. None of those
#   lanes knows the Mnemosyne inventory exists. Conversely
#   `mnemosyne-cli validate-workspace` (Layer A) validates the atomic
#   store's internal consistency (T1 cross-ref orphans, T2 frozen
#   ledger, T3/T4 style) but has no knowledge of which cargo features
#   gate real code. The two worlds were never joined.
#
#   Consequence (the drift this gate closes): when Phase 2 (R311fx)
#   wired pubsub-source-info / pubsub-priority / pubsub-congestion-
#   control / pubsub-express / pubsub-allow-loop / query-reply-err /
#   query-selector-parameters to real cfg-gated code, their inventory
#   status was deliberately left at "reserved" (mutate-deferred,
#   reported-only). The feature gates worked, every CI lane passed,
#   yet the catalog SSOT advertised them as un-built placeholders.
#   No functional test could catch a metadata-vs-code lie; only a
#   metadata-vs-code consistency gate can. This is that gate.
#
# Invariant enforced (per non-preset catalog atom A):
#   1. declared:  A is a `[features]` key in some crates/**/Cargo.toml
#                 (catches a phantom catalog entry with no cargo feature).
#   2. reserved => NOT gated:  status(A)=="reserved" must have ZERO
#                 `cfg(feature="A")` sites in crates/**/*.rs (a reserved
#                 atom that actually gates code is the drift class above).
#   3. active   => gated OR foundational:  status(A)=="active" must
#                 either have >=1 `cfg(feature="A")` gate site, OR appear
#                 in the FOUNDATIONAL allowlist below (capabilities that
#                 ship unconditionally and so carry no toggle by design).
#
# FOUNDATIONAL allowlist — atoms that are genuinely implemented and
# always compiled (no cfg gate by design), so `status=active` is honest
# even though no `cfg(feature=...)` site exists. Each entry is a curated
# judgment, not a mechanical fact, and must cite why:
#   keyexpr-canon / -literal / -mapping / -intersect / -includes /
#   -wildcard-single / -wildcard-double / -dollar-star
#       — the canon + glob/intersection matchers live in
#         wz-session-core/src/keyexpr_match.rs (R293 / R311dn) and are
#         used unconditionally on every subscriber/queryable match path.
#         lib.rs:70 documents keyexpr-canon as FOUNDATIONAL.
#   pubsub-sample
#       — the Sample receive surface (sample.rs) is always-on; cfg-off
#         would API-break the subscriber callback (feature_inventory
#         §5.8).
#   time-system-clock
#       — the wall-clock time source (wz-runtime-core/src/time.rs) is
#         the always-on default; HLC / source selection is the future
#         toggle (feature_inventory §5.18).
#   routing-client
#       — wz-runtime-tokio is unicast client-only today; the client
#         path is the always-on default, peer/router are the future
#         toggles (feature_inventory §5.15).
#   platform-linux
#       — platform identity is routed by Rust `target_os` cfg, not by a
#         cargo feature; the feature is a preset-composition label
#         (feature_inventory §5.14).
#
# Adding a new always-on capability => add it here WITH a rationale.
# Adding a new toggleable feature => it must carry a cfg(feature=...)
# gate; do NOT add it here to silence the gate.

set -euo pipefail

FOUNDATIONAL=(
    keyexpr-canon
    keyexpr-literal
    keyexpr-mapping
    keyexpr-intersect
    keyexpr-includes
    keyexpr-wildcard-single
    keyexpr-wildcard-double
    keyexpr-dollar-star
    pubsub-sample
    time-system-clock
    routing-client
    platform-linux
)

# ─── cwd discovery (repo root) ──────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v mnemosyne-cli >/dev/null 2>&1; then
    echo "audit-catalog-status SKIP (mnemosyne-cli not on PATH)"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "audit-catalog-status SKIP (python3 not on PATH)"
    exit 0
fi

INV_FILE="$(mktemp)"
trap 'rm -f "$INV_FILE"' EXIT
mnemosyne-cli query --list-inventory --json 2>/dev/null >"$INV_FILE"

FOUNDATIONAL_CSV="$(IFS=,; echo "${FOUNDATIONAL[*]}")"

FOUNDATIONAL_CSV="$FOUNDATIONAL_CSV" INV_FILE="$INV_FILE" python3 - <<'PY'
import json, os, re, subprocess, sys

inv = json.load(open(os.environ["INV_FILE"]))
entries = inv if isinstance(inv, list) else inv.get("entries", inv.get("inventory", []))
foundational = set(filter(None, os.environ["FOUNDATIONAL_CSV"].split(",")))

# atom -> status, excluding presets (presets are bundles, not atoms)
atoms = {}
for e in entries:
    aid = e.get("id") or e.get("inventory_id")
    if not aid or aid.startswith("preset-"):
        continue
    atoms[aid] = e.get("status")

# ground truth: declared cargo [features] keys across the workspace
declared = set()
for ct in subprocess.run(
    ["bash", "-c", "ls crates/*/Cargo.toml crates/*/*/Cargo.toml 2>/dev/null"],
    capture_output=True, text=True).stdout.split():
    txt = open(ct).read()
    m = re.search(r"\n\[features\]\n(.*?)(\n\[|\Z)", txt, re.S)
    if not m:
        continue
    for line in m.group(1).splitlines():
        mm = re.match(r"\s*([A-Za-z0-9_-]+)\s*=", line)
        if mm:
            declared.add(mm.group(1))

def has_gate(atom):
    # robust: `feature = "atom"` appears (in .rs only inside cfg/cfg_attr);
    # multi-line any(...) blocks put the feature on its own line, so a
    # same-line `cfg(` requirement would miss them.
    r = subprocess.run(
        ["grep", "-rIlE", r'feature *= *"%s"' % re.escape(atom),
         "crates", "--include=*.rs"],
        capture_output=True, text=True)
    return bool(r.stdout.strip())

fail_undeclared, fail_reserved_gated, fail_active_nogate = [], [], []
info_foundational = []

for atom in sorted(atoms):
    status = atoms[atom]
    gated = has_gate(atom)
    if atom not in declared:
        fail_undeclared.append(atom)
    if status == "reserved" and gated:
        fail_reserved_gated.append(atom)
    if status == "active" and not gated:
        if atom in foundational:
            info_foundational.append(atom)
        else:
            fail_active_nogate.append(atom)

ok = True
print("=== catalog status truthfulness audit ===")
print("  atoms=%d declared-cargo-features=%d" % (len(atoms), len(declared)))

if info_foundational:
    print("  foundational (active, always-on, no gate by design): %d" % len(info_foundational))
    for a in info_foundational:
        print("    - %s" % a)

if fail_undeclared:
    ok = False
    print("FAIL: catalog atom with NO cargo [features] key (phantom): %d" % len(fail_undeclared))
    for a in fail_undeclared:
        print("    - %s" % a)

if fail_reserved_gated:
    ok = False
    print("FAIL: status=reserved but atom GATES real code (stale drift): %d" % len(fail_reserved_gated))
    for a in fail_reserved_gated:
        print("    - %s  (set status=active, or remove the cfg gate)" % a)

if fail_active_nogate:
    ok = False
    print("FAIL: status=active but NO cfg gate and NOT foundational: %d" % len(fail_active_nogate))
    for a in fail_active_nogate:
        print("    - %s  (set status=reserved if unimplemented/folded, or add to FOUNDATIONAL with rationale)" % a)

if ok:
    print("catalog status truthfulness OK")
    sys.exit(0)
sys.exit(1)
PY
