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
#   3. active <=> gated:  status(A)=="active" iff A has >=1
#                 `cfg(feature="A")` gate site in crates/**/*.rs. `active`
#                 means EXACTLY "a real composition toggle the user can
#                 flip" — nothing else. A capability that is implemented
#                 but always compiled with no cfg toggle (foundational,
#                 e.g. keyexpr matchers / the Sample type / platform-linux
#                 routed by target_os) is status=reserved with a
#                 FOUNDATIONAL marker in its reason, NOT active — it is not
#                 a knob, so it does not belong in the active (toggle) set.
#                 (Invariant #2 already covers it: reserved => not gated.)
#   4. linked:  A carries a section_ref to its feature_inventory §5
#                 domain section, so the inventory entry is not an island
#                 disconnected from the design doc that describes it (and
#                 so the catalog cross-ref graph stays whole).
#
# Foundational atoms (implemented but always-on, no cfg toggle) are
# status=reserved, distinguished from inert-unimplemented reserved atoms
# by a "FOUNDATIONAL" prefix in their inventory reason. The gate does not
# need to special-case them: invariant #2 (reserved => not gated) already
# holds for them since they carry no cfg(feature=...) site. The
# FOUNDATIONAL/inert distinction is documentation (reason + feature_inventory
# §5), not a gate input. Examples of foundational reserved atoms:
#   keyexpr-canon / -literal / -mapping / -intersect / -includes /
#   -wildcard-single / -wildcard-double / -dollar-star  (matchers in
#       wz-session-core/src/keyexpr_match.rs, always-on on every match path)
#   pubsub-sample        (Sample receive surface; cfg-off would API-break)
#   time-system-clock    (wall-clock source; HLC is the future toggle)
#   routing-client       (unicast client-only; peer/router are future)
#   platform-linux       (routed by Rust target_os cfg, not a cargo feature)
#
# Adding a new toggleable feature => it MUST carry a cfg(feature=...) gate
# and be status=active. A new always-on capability => status=reserved with
# a FOUNDATIONAL reason; do NOT mark it active (it is not a toggle).

set -euo pipefail

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

INV_FILE="$INV_FILE" python3 - <<'PY'
import json, os, re, subprocess, sys

inv = json.load(open(os.environ["INV_FILE"]))
entries = inv if isinstance(inv, list) else inv.get("entries", inv.get("inventory", []))

# atom -> (status, section_ref), excluding presets (bundles, not atoms)
atoms = {}
section_ref = {}
reason = {}
for e in entries:
    aid = e.get("id") or e.get("inventory_id")
    if not aid or aid.startswith("preset-"):
        continue
    atoms[aid] = e.get("status")
    section_ref[aid] = e.get("section_ref")
    reason[aid] = (e.get("reason") or "").strip()

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

# R311y257 — invariant #5: the IMPLEMENTATION axis.
#
# `status` answers "is there a cfg knob?" -- it does NOT answer "is this
# built?". Those are different questions, and conflating them made the
# inventory unable to say what work remains: `reserved` lumps together the
# already-built-but-always-on (FOUNDATIONAL), the genuinely unbuilt, the
# deliberately excluded, and the built-under-another-name. The reason field
# carried that distinction only as free prose, so answering "what's left?"
# meant grepping English -- and two different greps disagreed (10 vs 27).
#
# The fix, within the closed Mnemosyne schema (no new field is permitted --
# anti-patterns #9): the FIRST token of every non-active atom's `reason` must
# be a tag from the closed set below, and the tag must agree with `status`.
# The tags answer "is there remaining implementation work, and of what kind?"
#
#   FOUNDATIONAL  built, always-on, no cfg knob          -> no work
#   PARTIAL       built (sometimes under another atom's  -> named residual
#                 cargo feature), with a named residual
#   UNVERIFIED    code portable by construction, but no  -> a CI lane, not code
#                 lane proves it (e.g. platform-macos)
#   UNBUILT       genuinely not implemented              -> all of it
#   BEYOND-PICO   deferred by design (P4 full-zenoh)     -> deferred
#   OUT-OF-SCOPE  deliberately excluded, re-openable     -> none, by decision
#   OBVIATED      no wz analog BY CONSTRUCTION           -> nothing to build
#   PHANTOM       does not exist in zenoh at all         -> nothing to build
#
# `active` needs no tag: it means built AND cfg-gated, so the implementation
# axis is unambiguous (invariant #3 already pins it).
#
# "What work remains" is now a query, not a grep:
#     UNBUILT + PARTIAL(residual) + UNVERIFIED(lanes)
IMPL_TAGS = {
    "FOUNDATIONAL": "reserved",
    "PARTIAL":      "reserved",
    "UNVERIFIED":   "reserved",
    "UNBUILT":      "reserved",
    "BEYOND-PICO":  "reserved",
    "OUT-OF-SCOPE": "reserved",
    "OBVIATED":     "deprecated",
    "PHANTOM":      "deprecated",
}

def impl_tag(atom):
    """First token of the reason, if it is a closed-set tag."""
    r = reason.get(atom, "")
    head = r.split(":")[0].split("(")[0].strip().upper()
    return head if head in IMPL_TAGS else None

fail_undeclared, fail_reserved_gated, fail_active_nogate = [], [], []
fail_unlinked = []
fail_untagged, fail_tag_status = [], []

for atom in sorted(atoms):
    status = atoms[atom]
    gated = has_gate(atom)
    if atom not in declared:
        fail_undeclared.append(atom)
    if status == "reserved" and gated:
        fail_reserved_gated.append(atom)
    if status == "active" and not gated:
        fail_active_nogate.append(atom)
    if not section_ref.get(atom):
        fail_unlinked.append(atom)
    if status != "active":
        tag = impl_tag(atom)
        if tag is None:
            fail_untagged.append(atom)
        elif IMPL_TAGS[tag] != status:
            fail_tag_status.append((atom, tag, status))

ok = True
active_n = sum(1 for a in atoms if atoms[a] == "active")
print("=== catalog status truthfulness audit ===")
print("  atoms=%d active=%d declared-cargo-features=%d" % (len(atoms), active_n, len(declared)))

# The implementation-axis roll-up: what this whole invariant exists to make
# answerable in one line.
tally = {}
for a in atoms:
    if atoms[a] == "active":
        continue
    t = impl_tag(a)
    if t:
        tally[t] = tally.get(t, 0) + 1
remaining = sorted(
    a for a in atoms
    if atoms[a] != "active" and impl_tag(a) in ("UNBUILT", "PARTIAL", "UNVERIFIED")
)
print("  implementation axis: active(built)=%d %s" % (
    active_n, " ".join("%s=%d" % (k, tally[k]) for k in sorted(tally))))
print("  REMAINING WORK (UNBUILT + PARTIAL + UNVERIFIED) = %d: %s" % (
    len(remaining), ", ".join(remaining) if remaining else "(none)"))

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
    print("FAIL: status=active but NO cfg gate: %d" % len(fail_active_nogate))
    for a in fail_active_nogate:
        print("    - %s  (active means a real cfg toggle; set status=reserved + FOUNDATIONAL reason if always-on, or add the cfg gate)" % a)

if fail_unlinked:
    ok = False
    print("FAIL: catalog atom with NO section_ref to its feature_inventory section: %d" % len(fail_unlinked))
    for a in fail_unlinked:
        print("    - %s  (set-inventory-section-ref --id %s --section <its §5 domain section>)" % (a, a))

if fail_untagged:
    ok = False
    print("FAIL: non-active atom whose reason does not START with an implementation tag: %d" % len(fail_untagged))
    print("    (without the tag the inventory cannot say whether this atom is built,")
    print("     so 'what work remains' degrades back to grepping English prose.)")
    for a in fail_untagged:
        print("    - %s  (prefix its reason with one of: %s)" % (a, " / ".join(sorted(IMPL_TAGS))))

if fail_tag_status:
    ok = False
    print("FAIL: implementation tag disagrees with status: %d" % len(fail_tag_status))
    for a, tag, status in fail_tag_status:
        print("    - %s  tag=%s implies status=%s, but status=%s"
              % (a, tag, IMPL_TAGS[tag], status))

if ok:
    print("catalog status truthfulness OK")
    sys.exit(0)
sys.exit(1)
PY
