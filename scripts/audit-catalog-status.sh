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
#   keyexpr-canon / -literal / -mapping / -intersect  (matchers in
#       wz-session-core/src/keyexpr_match.rs, always-on on every match path)
#   pubsub-sample        (Sample receive surface; cfg-off would API-break)
#   time-system-clock    (wall-clock source; HLC is the future toggle)
#   routing-client       (unicast client-only; peer/router are future)
#   platform-linux       (routed by Rust target_os cfg, not a cargo feature)
#
# R311y299 — this example list had ROTTED, and the rot is the whole point.
# It also named keyexpr-includes / -wildcard-single / -wildcard-double /
# -dollar-star as foundational-reserved. R311jf gave all four a real cfg
# toggle in keyexpr_match.rs and flipped them to status=active (live:
# 11 / 7 / 17 / 7 cfg sites respectively), and this comment was never
# updated. 4 of the 12 normative examples in THIS file -- the file whose
# entire purpose is to stop the impl axis living in un-checked prose --
# were themselves un-checked prose asserting a status the store refutes.
# Nothing gates a comment. That is the same defect class this gate exists
# to catch, one level up, and it is why the impl axis moves into a typed
# tag the gate reads (invariant #5) rather than into more prose.
#
# Adding a new toggleable feature => it MUST carry a cfg(feature=...) gate
# and be status=active. A new always-on capability => status=reserved with
# a FOUNDATIONAL reason; do NOT mark it active (it is not a toggle).

set -euo pipefail

# ─── cwd discovery (repo root) ──────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# R311y299 — the gate's own kill switch, and why it now has a required mode.
#
# A missing mnemosyne-cli disarmed A3 ENTIRELY: it exited 0 and every invariant
# went unchecked. Hosted CI installs mnemosyne-cli behind a `|| { warning; skip }`
# fallback, so one network blip disarmed the ONLY gate that joins the inventory to
# the source tree -- and release.yml runs A3 with no MNEMOSYNE_SKIP guard and has
# no A4 step at all, so nothing there would notice. A SKIP on a developer's box is
# honest (they may not have the tool); a SKIP where the job PROVISIONS the tool is
# a provisioning regression masquerading as success. Same rule as WZ_A4_REQUIRE /
# WZ_QZ_REQUIRE / WZ_Z_REQUIRE: "a should-run lane that SKIPs is the burn".
_a3_unavailable() {
    if [[ -n "${WZ_A3_REQUIRE:-}" ]]; then
        echo "audit-catalog-status FAIL — required (WZ_A3_REQUIRE set) but $1" >&2
        exit 1
    fi
    echo "audit-catalog-status SKIP ($1)"
    exit 0
}

if ! command -v mnemosyne-cli >/dev/null 2>&1; then
    _a3_unavailable "mnemosyne-cli not on PATH"
fi
if ! command -v python3 >/dev/null 2>&1; then
    _a3_unavailable "python3 not on PATH"
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

# R311y258 — gate sites, collected in ONE pass instead of one full-tree grep
# PER ATOM. The prior shape called `grep -rIlE 'feature *= *"<atom>"' crates`
# inside the per-atom loop, i.e. it re-scanned every .rs file in the workspace
# 212 times (once per catalog atom) to answer 212 independent membership
# questions against the SAME corpus. That is O(atoms x tree), and it cost 106s
# of a 22.5-minute run-ci -- the second-slowest layer, entirely from re-reading
# files it had already read.
#
# One grep now emits EVERY `feature = "..."` occurrence in crates/**/*.rs, and
# the names are folded into a set; `has_gate` becomes an O(1) lookup. The
# MATCHING SEMANTICS ARE UNCHANGED -- same `feature *= *"NAME"` pattern, same
# corpus, same "any occurrence counts" rule (the pattern is deliberately not
# anchored to `cfg(`, because a multi-line `any(...)` block puts the feature on
# its own line and a same-line `cfg(` requirement would miss it). So the audit's
# verdict for every atom is bit-identical; only the cost changes.
_gate_names = set()
_r = subprocess.run(
    ["grep", "-rIhoE", r'feature *= *"[A-Za-z0-9_-]+"',
     "crates", "--include=*.rs"],
    capture_output=True, text=True)
for _line in _r.stdout.splitlines():
    _m = re.search(r'"([A-Za-z0-9_-]+)"', _line)
    if _m:
        _gate_names.add(_m.group(1))

def has_gate(atom):
    return atom in _gate_names

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
# R311y299 — the premise that used to stand here was FALSE, and it cost the
# audit its headline number. It read:
#
#     "`active` needs no tag: it means built AND cfg-gated, so the
#      implementation axis is unambiguous (invariant #3 already pins it)."
#
# Invariant #3 pins `active <=> >=1 cfg site`. That asserts A KNOB EXISTS. It
# says NOTHING about whether the capability behind the knob is finished --
# and :39-43 of this file says so outright: `active` means EXACTLY "a real
# composition toggle the user can flip" -- NOTHING ELSE. The two comments
# contradicted each other, and the exempting one won at :212/:228/:235: an
# atom that was active + cfg-gated + HALF-BUILT was invisible to REMAINING
# WORK by construction.
#
# The grammar then made the truth unsayable. PARTIAL mapped to `reserved`,
# and `reserved` requires ZERO cfg sites (invariant #2) -- so an atom with a
# real knob COULD NOT be marked PARTIAL. R311y296 found query-consolidation
# half-built (Q_C transmit wired, apply-half unbuilt), had nowhere in the
# grammar to put it, and wrote it into prose. The grammar forced that.
#
# The fix: tag -> status becomes a RELATION (a set of admissible statuses)
# instead of a function, so the product of the two axes is expressible.
# PARTIAL widens to active; COMPLETE is the new "active, built, no residual".
#
# The tag is REQUIRED on every non-active atom. On an ACTIVE atom it is
# OPTIONAL-BUT-COUNTED (reported as UNAUDITED), deliberately -- see the
# UNAUDITED note at the roll-up below. It is NOT silently skipped.
#
# "What work remains" is a query, not a grep -- but only over the atoms whose
# impl axis has actually been audited:
#     UNBUILT + PARTIAL(residual) + UNVERIFIED(lanes)   >= a LOWER BOUND
IMPL_TAGS = {
    "COMPLETE":     {"active"},
    "FOUNDATIONAL": {"reserved"},
    "PARTIAL":      {"reserved", "active"},
    "UNVERIFIED":   {"reserved"},
    "UNBUILT":      {"reserved"},
    "BEYOND-PICO":  {"reserved"},
    "OUT-OF-SCOPE": {"reserved"},
    "OBVIATED":     {"deprecated"},
    "PHANTOM":      {"deprecated"},
}

# Tags that assert remaining implementation work of some kind.
TAGS_REMAINING = ("UNBUILT", "PARTIAL", "UNVERIFIED")

def _head(atom):
    """The reason's first token, whether or not it is a legal tag."""
    r = reason.get(atom) or ""
    return r.split(":")[0].split("(")[0].strip().upper()

def impl_tag(atom):
    """First token of the reason, if it is a closed-set tag."""
    return _head(atom) if _head(atom) in IMPL_TAGS else None

fail_undeclared, fail_reserved_gated, fail_active_nogate = [], [], []
fail_unlinked = []
fail_untagged, fail_tag_status, fail_bad_tag = [], [], []
unaudited = []

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

    tag = impl_tag(atom)
    if tag is not None:
        # The tag -> status RELATION: a tag is legal on a SET of statuses.
        if status not in IMPL_TAGS[tag]:
            fail_tag_status.append((atom, tag, status))
    elif status != "active":
        # R311y299 — separate "typo'd a tag" from "wrote no tag". impl_tag()
        # returns None for both, so the old single message misdiagnosed
        # `BEYOND_PICO` / `OUT OF SCOPE` as a MISSING tag and printed the
        # wrong instruction. A head token that is ALL-CAPS and tag-shaped but
        # not in the closed set is a typo; anything else is genuinely untagged.
        head = _head(atom)
        if head and re.fullmatch(r"[A-Z][A-Z _-]{2,}", head):
            fail_bad_tag.append((atom, head))
        else:
            fail_untagged.append(atom)
    else:
        # status == "active" and no tag. NOT a failure yet -- but NOT silently
        # skipped either, which is exactly what this gate did until R311y299.
        unaudited.append(atom)

ok = True
active_n = sum(1 for a in atoms if atoms[a] == "active")
print("=== catalog status truthfulness audit ===")
print("  atoms=%d active=%d declared-cargo-features=%d" % (len(atoms), active_n, len(declared)))

# The implementation-axis roll-up.
#
# R311y299 — this used to print `active(built)=132` and a bare
# `REMAINING WORK = N`, having skipped every active atom (:228-230 of the old
# file). Both were assertions the audit had never checked: `active` means "has
# a knob", so `active(built)=132` restated the knob count while CLAIMING the
# build count, and REMAINING WORK excluded 132 of 212 atoms by construction.
# The number was not merely incomplete -- it was presented as complete.
#
# It is now reported as a LOWER BOUND with the unaudited remainder named. The
# tally counts every TAGGED atom regardless of status (an active PARTIAL is
# remaining work exactly as much as a reserved one).
#
# Why UNAUDITED is counted rather than failed: tagging the 132 active atoms is
# a per-atom CODE READ, not a prose transcription. The reason prose is known to
# have rotted in BOTH directions -- storage-aligner's reason says "driver A8 +
# facade forward A9 pending" against a live 1178-line driver and a shipped
# facade forward, and keyexpr-includes' says "no internal consumer yet" against
# 6 live consumers. Transcribing that prose into a typed tag would launder
# stale prose into a field that LOOKS authoritative: prose rots, and a typed
# tag certified by prose rots just as fast, only louder. So the tags are earned
# a batch at a time, and until UNAUDITED reaches 0 this gate reports what it
# does not know instead of asserting a completeness it never checked. When
# UNAUDITED hits 0, promote the active arm to fail_untagged (one-line change)
# and the bound becomes exact.
tally = {}
for a in atoms:
    t = impl_tag(a)
    if t:
        tally[t] = tally.get(t, 0) + 1
remaining = sorted(a for a in atoms if impl_tag(a) in TAGS_REMAINING)
print("  implementation axis: %s" % (
    " ".join("%s=%d" % (k, tally[k]) for k in sorted(tally)) or "(nothing tagged)"))
print("  impl axis UNAUDITED (active, no tag) = %d of %d active" % (
    len(unaudited), active_n))
print("  REMAINING WORK (UNBUILT + PARTIAL + UNVERIFIED) >= %d%s: %s" % (
    len(remaining),
    "  [LOWER BOUND -- %d unaudited active atoms not counted]" % len(unaudited)
    if unaudited else "  [EXACT -- every atom's impl axis is tagged]",
    ", ".join(remaining) if remaining else "(none)"))

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

if fail_bad_tag:
    ok = False
    print("FAIL: reason STARTS with an unrecognized tag-shaped token (typo?): %d"
          % len(fail_bad_tag))
    for a, head in fail_bad_tag:
        print("    - %s  head=`%s` is not in the closed set (%s)"
              % (a, head, " / ".join(sorted(IMPL_TAGS))))

if fail_tag_status:
    ok = False
    print("FAIL: implementation tag is not legal on this status: %d" % len(fail_tag_status))
    for a, tag, status in fail_tag_status:
        print("    - %s  tag=%s is legal on {%s}, but status=%s"
              % (a, tag, ", ".join(sorted(IMPL_TAGS[tag])), status))

if ok:
    print("catalog status truthfulness OK")
    sys.exit(0)
sys.exit(1)
PY
