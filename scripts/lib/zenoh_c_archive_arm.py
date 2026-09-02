#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2278 (no register item) — WHICH BUILD OF zenoh-c UPSTREAM SHIPS IS A
DERIVED FACT WITH ONE HOME, AND EVERY SENTENCE THAT STATES IT IS ADJUDICATED.

## The citation, and why it is the escape hatch rather than a number

This answers the numeric open-debt register's item 612, which lives in the
operator's notes rather than in the store, so `gate_provenance_lint`'s item
grammar cannot resolve it. `prose_feature_gate.py` set the precedent for that
position: declare the escape hatch on the first line and name the item in the
body, because a citation the lint cannot check is not a citation.

## The defect this is the instrument for

Upstream's release workflow decides, per RELEASE, which `Z_FEATURE_*` set the
standalone package it publishes is built with. That is a PER-VERSION fact.
This tree wrote it down as a timeless one, in nine places, and then moved the
pin — R2229, 1.5.0 to 1.10.0 — without re-deriving any of them. Three sites
were corrected as their own rounds noticed them (R2256, R2258) and the rest
were not, so the tree carried both answers at once and a consumer opening the
manifest to choose a feature read the older one.

The failure is not "prose drifted from code". Nothing in the tree could have
been consulted: the fact belongs to upstream, and no wz file derived it.

## What this file is

The ONE home for the fact, plus the two derivations that judge it, plus the
gate that holds every sentence in the tree to it.

  * `--arm` prints it. Shell consumers read it here rather than restating it.
  * `--derive` re-derives it from upstream's OWN release workflow in the
    pinned checkout, and cross-checks the installed oracle's generated
    `zenoh_configure.h`. Both inputs are machine-local, so this is armed:
    absent input SKIPs unless `--require`, and `--require` belongs on any job
    that has just run `install-zenoh-c.sh`.
  * `--check` needs no external input, so it runs in Layer C0 on every push.
    It binds the constant to the version pin, derives the population of
    sentences that state the fact, and adjudicates each one.

## Why the constant exists at all when a derivation is available

The derivation's inputs are a source checkout and an install prefix. Neither
is in any clone, so a gate that required them would SKIP on the fast lane —
green, having read nothing. So the fact is DATA here, judged by upstream where
upstream is present, and BOUND to the version pin everywhere: `--check` reads
`ZENOH_C_VERSION`'s default out of `scripts/install-zenoh-c.sh` and refuses
when it has moved. A pin bump therefore cannot land without re-deriving this,
which is the ratchet the 1.5.0-to-1.10.0 move did not have.

## The adjudication, stated as a rule rather than as a phrase list

A sentence that mentions the standalone package AND carries arm vocabulary
must NAME an arm, in the id form the four provisioning arms already use; the
one NEAREST the mention must be the derived one; and any `Z_FEATURE_*` macro
it names must be one that arm actually carries. A stale sentence cannot pass
by accident, because the id it would have to carry is the one the fact says
today.

Nearest rather than only, and that is a measurement rather than a taste. A
sentence saying the package resolves one way "so the other arm now needs a
source build" is CORRECT and names two ids; a sentence listing the package's
arm beside a different build's is STALE and names two ids. What separates them
is which id sits next to the package, so that is what is read.

A banned-spelling list was the alternative and it is a FLOOR, which this tree
has measured twice (open-debt item 190, and `prose_feature_gate`'s own
header): a sentence that correctly describes a superseded reading and one that
failed to follow it are the same string to a phrase list. Requiring a FORM
adjudicated against a derivation has neither problem.

## There is NO history escape, and that is a measurement rather than a stance

The obvious shape here is R2239's: let a sentence name the version it was
measured at and hold it to that release instead of to the pin. R2278 built
that, then measured whether anything needed it, and nothing did — because the
claim this file was written for was never true at EITHER pin. Both published
packages were fetched and read: 1.5.0's `zenoh_configure.h` declares both axes
and so does 1.10.0's. The tree's older reading came from an install that was
not the package.

So the escape had zero users, and an escape with zero users is attack surface
with nothing to weigh against it (the rule this tree states as "an exemption
no other derivation adjudicates is a way out"). It was removed rather than
shipped unused.

A refutation is still writable, because the rule is ADJACENCY rather than
exclusivity: "the package is the `unstable-shm` build, and was never
`nounstable`" puts the true id next to the package and passes. If a future
release ever diverges from an earlier one, THAT is when a version-qualified
form earns its place, with a real sentence needing it.

## The manifest is a consumer's file, so it states BOTH arms

The `[features]` table is what a consumer opens to choose a build, and item
612 is a report from one who did. Which arm the DEFAULT feature set models is
derived here from that table's own contents — not from its prose — and the
table is required to name it AND to name the package's arm. Where those differ
the consumer reads it in the file they already have open; nothing is left to a
reader who knows to look elsewhere.

## Scope, stated so the green is not read wider than it is

The population is COMMENT and Markdown prose over tracked files. Code is not
scanned: a claim in this class is written in prose, and paragraph-joining over
code lines makes neighbouring literals into one sentence (a cache key beside a
provisioning step, measured while this was written). What that leaves uncovered
is a claim inside a string literal; nothing in the tree currently states the
fact that way, and `--check` reports its population every run so a zero can
never read as a pass.

`docs/.atomic/**` is out, and that is a rule rather than a taste: the frozen
ledger must keep the reading each round actually had.

⚠ THIS FILE CANNOT SPELL A FALSE EXAMPLE. It is tracked and the scan reads it,
so the shapes it refuses are described rather than written; the selftest builds
them in a temporary directory.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys
import tempfile

# ── the fact, and the pin it is bound to ─────────────────────────────────────
#
# Derived 2026-09-02 from eclipse-zenoh/zenoh-c at tag 1.10.0, by two readings
# that agree: the `Build standalone` step of upstream's own release workflow
# passes both axes ON, and the `zenoh_configure.h` that ships inside the
# resulting package declares both. `--derive` re-runs exactly that.
PIN = "1.10.0"
ARCHIVE_ARM = "unstable-shm"

# The four ids are `install-zenoh-c-arm.sh`'s argument vocabulary and
# `zenoh-c-oracle-arm.sh`'s output vocabulary. They are not spelled twice on
# purpose -- `--check` holds this tuple to the set the tree actually uses.
ARMS = ("nounstable", "unstable", "nounstable-shm", "unstable-shm")

# The two CMake switches upstream's build exposes, and the axis each drives.
AXES = {
    "UNSTABLE_API": "ZENOHC_BUILD_WITH_UNSTABLE_API",
    "SHARED_MEMORY": "ZENOHC_BUILD_WITH_SHARED_MEMORY",
}

ROOT = pathlib.Path(__file__).resolve().parents[2]


def arm_id(unstable: bool, shm: bool) -> str:
    """The id form the provisioning scripts use, from the two axes."""
    return ("unstable" if unstable else "nounstable") + ("-shm" if shm else "")


def arm_axes(arm: str) -> dict[str, bool]:
    """Invert `arm_id`, by search rather than by a second table."""
    for unstable in (False, True):
        for shm in (False, True):
            if arm_id(unstable, shm) == arm:
                return {"UNSTABLE_API": unstable, "SHARED_MEMORY": shm}
    raise ValueError(f"not an arm id: {arm!r}")


# ── the population: prose, over tracked files ────────────────────────────────

# Extension -> the comment leaders that introduce prose in it. Markdown has no
# leader and is prose throughout, which is why it maps to the empty tuple.
LEADERS: dict[str, tuple[str, ...]] = {
    ".rs": ("//!", "///", "//"),
    ".c": ("//",),
    ".h": ("//",),
    ".sh": ("#",),
    ".py": ("#",),
    ".toml": ("#",),
    ".yml": ("#",),
    ".yaml": ("#",),
    ".md": (),
}

EXCLUDED_PREFIXES = ("docs/.atomic/", "vendor/", "out/", "target/")

# What names the thing whose build arm is at issue. Deliberately WIDE: an
# over-inclusive sweep is the safe direction here, because a sentence only
# reaches a verdict once it ALSO carries arm vocabulary, and "the apt archive"
# never does.
ARCHIVE_RE = re.compile(r"\barchives?\b|install-zenoh-c\.sh", re.IGNORECASE)

# What makes a sentence a CLAIM about the arm rather than a mention of the
# package. Every alternative here is a spelling this tree uses.
ARM_VOCAB_RE = re.compile(
    r"Z_FEATURE_UNSTABLE_API"
    r"|Z_FEATURE_SHARED_MEMORY"
    r"|zenoh-c-no-unstable-api"
    r"|zenoh-c-shared-memory"
    r"|(?<![\w-])no-?unstable(-shm)?(?![\w-])"
    r"|(?<![\w-])unstable(-shm)?(?![\w-])"
    r"|\bshared[- ]memory\b"
    r"|\bSHM\b",
    re.IGNORECASE,
)

# An arm id NAMED, in prose. Backticked, and that is the measurement rather
# than a style rule: bare `unstable` is also an English adjective, so "built
# without unstable" would otherwise read as naming an arm and satisfy the very
# rule it violates. The tree already writes ids this way where it names them.
# Longest first, so `unstable-shm` is never read as `unstable`.
ARM_ID_RE = re.compile(
    r"`(nounstable-shm|unstable-shm|nounstable|unstable)`"
)

# The same ids in ANY form. Used only to establish that each id this file
# carries is one the tree actually uses -- a vocabulary check, not a reading.
ARM_TOKEN_RE = re.compile(
    r"(?<![\w-])(nounstable-shm|unstable-shm|nounstable|unstable)(?![\w-])"
)

Z_FEATURE_RE = re.compile(r"Z_FEATURE_(UNSTABLE_API|SHARED_MEMORY)")

# The two manifest features that select an arm, and the axis each moves. The
# `no-` one is INVERTED, which is why this is a table of (feature, axis, sense)
# rather than a pair of names.
MANIFEST_FEATURES = {
    "zenoh-c-no-unstable-api": ("UNSTABLE_API", False),
    "zenoh-c-shared-memory": ("SHARED_MEMORY", True),
}

CAPI_C_MANIFEST = "crates/wz-capi-c/Cargo.toml"

# Where the arm is SELECTED and where it is RUN. Both are read rather than
# assumed: the selector expresses an oracle's arm as ADDITIONS to the default,
# which is only correct while the default sits at the origin of both axes, and
# the lane legs are what make a default that differs from the published build
# cost something instead of merely being declared.
RUNCI = "scripts/run-ci.sh"
ORACLE_FN = "_runci_build_capi_c_for_oracle"

# A period/question/bang that ends a sentence: followed by space and something
# that starts one. `install-zenoh-c.sh` and `1.10.0` do not match, which is the
# whole reason for the lookahead.
SENTENCE_SPLIT_RE = re.compile(r"(?<=[\w)\]`\"*])[.?!]\s+(?=[A-Z(`*\[])")


def tracked_files() -> list[pathlib.Path]:
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"],
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    keep = []
    for rel in out:
        if rel.startswith(EXCLUDED_PREFIXES):
            continue
        if pathlib.Path(rel).suffix not in LEADERS:
            continue
        keep.append(ROOT / rel)
    return keep


def prose_paragraphs(path: pathlib.Path, text: str) -> list[str]:
    """Contiguous runs of PROSE lines, joined, with the leaders stripped.

    A code line ends a paragraph rather than joining one: joining across code
    makes two unrelated literals into a sentence, and that reads as a claim
    nobody wrote.
    """
    leaders = LEADERS[path.suffix]
    paragraphs: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        body: str | None = None
        if not leaders:
            body = stripped
        else:
            for leader in leaders:
                if stripped.startswith(leader):
                    body = stripped[len(leader):].strip()
                    break
        if body:
            current.append(body)
        else:
            if current:
                paragraphs.append(" ".join(current))
                current = []
    if current:
        paragraphs.append(" ".join(current))
    return paragraphs


def sentences(paragraph: str) -> list[str]:
    return [s.strip() for s in SENTENCE_SPLIT_RE.split(paragraph) if s.strip()]


def nearest_arm_id(sentence: str) -> str | None:
    """The arm id sitting closest to a mention of the package.

    Distance is between match spans, so a sentence that names the package
    twice is judged from whichever mention the id is actually beside.
    """
    ids = list(ARM_ID_RE.finditer(sentence))
    if not ids:
        return None
    anchors = list(ARCHIVE_RE.finditer(sentence))
    if not anchors:
        return None

    def gap(m: re.Match[str], a: re.Match[str]) -> int:
        if m.end() <= a.start():
            return a.start() - m.end()
        if a.end() <= m.start():
            return m.start() - a.end()
        return 0

    return min(ids, key=lambda m: min(gap(m, a) for a in anchors)).group(1)


def adjudicate(sentence: str, arm: str) -> list[str]:
    """Every way this sentence disagrees with `arm`. Empty means it agrees."""
    faults: list[str] = []
    nearest = nearest_arm_id(sentence)
    if nearest is None:
        faults.append(f"states the arm without naming `{arm}`")
    elif nearest != arm:
        faults.append(f"puts the `{nearest}` arm next to the package, not `{arm}`")
    axes = arm_axes(arm)
    for macro in sorted(set(Z_FEATURE_RE.findall(sentence))):
        if not axes[macro]:
            faults.append(f"names Z_FEATURE_{macro}, which `{arm}` does not carry")
    return faults


def scan(files: list[pathlib.Path], arm: str) -> tuple[int, int, list[str]]:
    """(mentions, adjudicated, findings) over the given files."""
    mentions = 0
    adjudicated = 0
    findings: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for paragraph in prose_paragraphs(path, text):
            for sentence in sentences(paragraph):
                if not ARCHIVE_RE.search(sentence):
                    continue
                mentions += 1
                if not ARM_VOCAB_RE.search(sentence):
                    continue
                adjudicated += 1
                for fault in adjudicate(sentence, arm):
                    rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
                    findings.append(f"{rel}: {fault}\n      {sentence[:200]}")
    return mentions, adjudicated, findings


def features_table(manifest: pathlib.Path) -> dict[str, list[str]]:
    """The `[features]` table: each feature and the list it enables."""
    text = manifest.read_text(encoding="utf-8")
    section = re.search(r"^\[features\]$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if not section:
        raise ValueError(f"{manifest}: no [features] table")
    table: dict[str, list[str]] = {}
    for m in re.finditer(r"^([A-Za-z0-9_-]+)\s*=\s*\[(.*?)\]",
                         section.group(1), re.M | re.S):
        table[m.group(1)] = re.findall(r'"([^"]+)"', m.group(2))
    return table


def default_closure(table: dict[str, list[str]]) -> set[str]:
    """What `default` enables, transitively -- as cargo would count it."""
    closure: set[str] = set()
    pending = list(table.get("default", []))
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        closure.add(name)
        pending.extend(table.get(name, []))
    return closure


def arm_of(enabled: set[str]) -> str:
    """The arm a build with exactly `enabled` features models."""
    axes = {"UNSTABLE_API": True, "SHARED_MEMORY": False}
    for feature, (axis, sense) in MANIFEST_FEATURES.items():
        if feature in enabled:
            axes[axis] = sense
    return arm_id(axes["UNSTABLE_API"], axes["SHARED_MEMORY"])


def arm_features(arm: str) -> set[str]:
    """The manifest features a build must enable to BE `arm`.

    Derived by matching each feature's (axis, sense) against the arm's axes, so
    it cannot drift from `MANIFEST_FEATURES` the way a second table would.
    """
    want = arm_axes(arm)
    return {feature for feature, (axis, sense) in MANIFEST_FEATURES.items()
            if want[axis] == sense}


def manifest_default_arm(manifest: pathlib.Path) -> str:
    """The arm `wz-capi-c`'s DEFAULT feature set models, from the table itself.

    Read out of the `[features]` table rather than out of the prose beside it,
    which is the whole point: the prose is what this file adjudicates.
    """
    table = features_table(manifest)
    for feature in MANIFEST_FEATURES:
        if feature not in table:
            raise ValueError(f"{manifest}: [features] has no `{feature}`")
    return arm_of(default_closure(table))


def shell_function(path: pathlib.Path, name: str) -> str:
    """One shell function's body: `name() {` to the closing brace in column 0."""
    text = path.read_text(encoding="utf-8")
    head = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*$", text, re.M)
    if not head:
        raise ValueError(f"{path}: no function `{name}`")
    tail = re.compile(r"^\}$", re.M).search(text, head.end())
    if not tail:
        raise ValueError(f"{path}: `{name}` has no closing brace in column 0")
    return text[head.end():tail.start()]


def capi_c_test_feature_sets(text: str) -> list[set[str]]:
    """The feature set of every `cargo test -p wz-capi-c` invocation in `text`.

    COMMENT lines are dropped first. R2287 (item 624): the divergence arm pays
    its bill from this list, and a commented-out leg is not a leg -- the same
    confusion `hook_gate_boundary_gate.py` records for a fix hint that PRINTS a
    command. Measured on the shipped `run-ci.sh`: dropping comments leaves the
    verdict identical (2 legs, 1 paying), and only the vacuous branch closes.
    """
    text = "\n".join(line for line in text.splitlines()
                     if not re.match(r"^\s*#", line))
    out: list[set[str]] = []
    for call in re.finditer(r"cargo test -p wz-capi-c([^\n]*)", text):
        feats: set[str] = set()
        for spelled in re.finditer(r"--features\s+([A-Za-z0-9_,-]+)",
                                   call.group(1)):
            feats |= {f for f in spelled.group(1).split(",") if f}
        out.append(feats)
    return out


# ── the two derivations ──────────────────────────────────────────────────────

def derive_from_upstream(ref: pathlib.Path) -> str:
    """The arm upstream's OWN release workflow builds the package with.

    The defaults come from `CMakeLists.txt`'s `declare_cache_var`, so a switch
    the workflow omits is read from upstream rather than assumed here.
    """
    cmakelists = ref / "CMakeLists.txt"
    workflow = ref / ".github" / "workflows" / "release.yml"
    if not cmakelists.is_file() or not workflow.is_file():
        raise FileNotFoundError(f"{ref} is not a zenoh-c source checkout")

    cmake_text = cmakelists.read_text(encoding="utf-8")
    values: dict[str, bool] = {}
    for axis, switch in AXES.items():
        m = re.search(
            rf"declare_cache_var\(\s*{switch}\s+(TRUE|FALSE|ON|OFF)\b", cmake_text
        )
        if not m:
            raise ValueError(f"{cmakelists}: no declared default for {switch}")
        values[axis] = m.group(1) in ("TRUE", "ON")

    lines = [
        ln for ln in workflow.read_text(encoding="utf-8").splitlines()
        if "cmake" in ln and "CPACK_PACKAGE_NAME" in ln
    ]
    if not lines:
        raise ValueError(f"{workflow}: no packaging cmake invocation found")
    arms = set()
    for line in lines:
        seen = dict(values)
        for axis, switch in AXES.items():
            m = re.search(rf"-D{switch}=(ON|OFF|TRUE|FALSE)\b", line)
            if m:
                seen[axis] = m.group(1) in ("ON", "TRUE")
        arms.add(arm_id(seen["UNSTABLE_API"], seen["SHARED_MEMORY"]))
    if len(arms) != 1:
        raise ValueError(
            f"{workflow}: packaging steps disagree on the arm: {sorted(arms)}"
        )
    return arms.pop()


def derive_from_install(prefix: pathlib.Path) -> str:
    """The arm the INSTALLED oracle is, through the shared resolver.

    Not an inlined copy: `test-zenoh-c-oracle-arm.sh` drives that file on all
    four combinations, and a probe against a copy proves nothing about what
    ships.
    """
    resolver = ROOT / "scripts" / "lib" / "zenoh-c-oracle-arm.sh"
    proc = subprocess.run(
        ["bash", str(resolver), str(prefix)], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise FileNotFoundError(proc.stderr.strip() or f"no oracle at {prefix}")
    return proc.stdout.strip()


def installer_pin() -> str:
    text = (ROOT / "scripts" / "install-zenoh-c.sh").read_text(encoding="utf-8")
    m = re.search(r'ZENOH_C_VERSION="\$\{ZENOH_C_VERSION:-([^}"]+)\}"', text)
    if not m:
        raise ValueError(
            "install-zenoh-c.sh: could not read ZENOH_C_VERSION's default"
        )
    return m.group(1)


# ── the arm lattice (open-debt item 616) ─────────────────────────────────────

def check_lattice(manifest: pathlib.Path,
                  runci: pathlib.Path) -> tuple[int, list[str], list[str]]:
    """Where the DEFAULT sits, and what the divergence it accepts has to cost.

    Item 616 asked whether the default should move to the build upstream ships.
    It cannot, and the reason is a property of cargo rather than a preference:
    features are ADDITIVE, so every arm has to be `default + <features>`. With
    the default empty all four arms are reachable that way; with the shm axis in
    it, the two no-shm arms would need `--no-default-features` -- which a
    dependent enabling the default takes straight back, so the crate would be
    the wrong size in exactly the build a consumer assembles by accident.

    That decision leaves a DIVERGENCE, and a divergence nobody exercises is a
    declaration. So it is priced: a named lane leg has to RUN the feature set
    that reaches upstream's build, and the selector that turns an installed
    header into a build has to name every axis and add rather than subtract.

    Returns `(rc, report, failures)` so the selftest can read the verdict
    instead of parsing what was printed.
    """
    rc = 0
    report: list[str] = []
    fail: list[str] = []

    table = features_table(manifest)
    declared = set(table) - {"default"}
    # No exemption list on purpose. An unclassified feature is a decision a
    # round has to make -- the lattice below is SIZED from MANIFEST_FEATURES,
    # so a feature that table does not know makes it the wrong size.
    for extra in sorted(declared - set(MANIFEST_FEATURES)):
        fail.append(f"  archive-arm FAIL: {CAPI_C_MANIFEST} declares `{extra}`, "
                    f"which\n    MANIFEST_FEATURES does not classify. The arm "
                    f"lattice is sized from that\n    table, so an unclassified "
                    f"feature makes it the wrong size: classify it,\n    or move "
                    f"it out of this crate.")
        rc = 1
    for gone in sorted(set(MANIFEST_FEATURES) - declared):
        fail.append(f"  archive-arm FAIL: MANIFEST_FEATURES carries `{gone}` and "
                    f"the\n    manifest no longer declares it.")
        rc = 1

    closure = default_closure(table)
    default_arm = arm_of(closure)
    lost = sorted(arm for arm in ARMS if not arm_features(arm) >= closure)
    if lost:
        fail.append(f"  archive-arm FAIL: the default feature set "
                    f"{sorted(closure)} puts\n    "
                    f"{', '.join('`%s`' % a for a in lost)} out of ADDITIVE reach "
                    f"-- those arms would need\n    `--no-default-features`, and a "
                    f"dependent that enables the default takes\n    it back. The "
                    f"default has to sit at the ORIGIN of every axis.")
        rc = 1

    divergence = arm_features(ARCHIVE_ARM) - closure
    legs = capi_c_test_feature_sets(runci.read_text(encoding="utf-8"))
    paying = [feats for feats in legs if feats >= divergence]
    if not divergence:
        report.append(f"  archive-arm: the default models `{default_arm}`, the "
                      f"build upstream ships -- nothing to price")
    elif not paying:
        fail.append(f"  archive-arm FAIL: the default models `{default_arm}`, "
                    f"upstream ships\n    `{ARCHIVE_ARM}`, and no `cargo test -p "
                    f"wz-capi-c` leg in {RUNCI} enables\n    {sorted(divergence)}. "
                    f"The divergence is accepted BECAUSE the other arm is\n    "
                    f"exercised; with no leg running it, moving the default is "
                    f"the only\n    honest option left.")
        rc = 1

    try:
        selector = shell_function(runci, ORACLE_FN)
    except ValueError as exc:
        fail.append(f"  archive-arm FAIL: {exc}. The selector is what turns an "
                    f"installed\n    header into a build; a selector this gate "
                    f"cannot find is one it cannot\n    grade.")
        rc = 1
        selector = None
    if selector is not None:
        for feature in sorted(MANIFEST_FEATURES):
            if not re.search(rf"--features\s+{re.escape(feature)}\b", selector):
                fail.append(f"  archive-arm FAIL: `{ORACLE_FN}` never adds\n"
                            f"    `--features {feature}`, so an oracle on that "
                            f"axis is served the default\n    build -- a size "
                            f"mismatch, which is a corrupted caller frame rather "
                            f"than\n    a link error.")
                rc = 1
        if "--no-default-features" in selector:
            fail.append(f"  archive-arm FAIL: `{ORACLE_FN}` uses "
                        f"`--no-default-features`.\n    Selecting an arm by "
                        f"SUBTRACTION means the default is no longer the\n    "
                        f"origin, and cargo hands a dependent the default back.")
            rc = 1

    report.append(f"  archive-arm: {len(ARMS)} arm(s) from "
                  f"{len(MANIFEST_FEATURES)} axis(es), all additively reachable "
                  f"from the default {sorted(closure)}; divergence "
                  f"{sorted(divergence)} run by {len(paying)} of {len(legs)} "
                  f"wz-capi-c test leg(s)")
    return rc, report, fail


# ── modes ────────────────────────────────────────────────────────────────────

def cmd_check() -> int:
    rc = 0

    # 1. The constant is bound to the pin. A bump re-opens the derivation.
    pin = installer_pin()
    if pin != PIN:
        print(
            f"  archive-arm FAIL: install-zenoh-c.sh pins zenoh-c {pin} and this\n"
            f"    file's arm was derived at {PIN}. Which build upstream publishes is\n"
            f"    a per-release fact: re-derive with `--derive --require` against a\n"
            f"    {pin} checkout and move PIN and ARCHIVE_ARM together.",
            file=sys.stderr,
        )
        rc = 1

    files = tracked_files()

    # 2. The id vocabulary is EQUAL to what the tree uses, not a subset of it.
    used: set[str] = set()
    for path in files:
        try:
            used |= set(ARM_TOKEN_RE.findall(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
    if used != set(ARMS):
        for dead in sorted(set(ARMS) - used):
            print(f"  archive-arm FAIL: `{dead}` is in ARMS and occurs nowhere.",
                  file=sys.stderr)
        for extra in sorted(used - set(ARMS)):
            print(f"  archive-arm FAIL: the tree uses the arm id `{extra}`, "
                  f"which ARMS does not carry.", file=sys.stderr)
        rc = 1

    # 3. The manifest a consumer opens names the arm its default models AND the
    #    arm the package is. Derived from the table, checked against the prose.
    manifest = ROOT / CAPI_C_MANIFEST
    default_arm = manifest_default_arm(manifest)
    features_prose = " ".join(
        line.strip().lstrip("#").strip()
        for line in re.search(
            r"^\[features\]$(.*?)(?=^\[|\Z)",
            manifest.read_text(encoding="utf-8"), re.M | re.S,
        ).group(1).splitlines()
        if line.strip().startswith("#")
    )
    for arm, role in ((default_arm, "its default feature set models"),
                      (ARCHIVE_ARM, "upstream publishes")):
        if not ARM_ID_RE.search(features_prose) or arm not in set(
            ARM_ID_RE.findall(features_prose)
        ):
            print(
                f"  archive-arm FAIL: {CAPI_C_MANIFEST}'s [features] table does not\n"
                f"    name `{arm}`, the arm {role}. This table is what a consumer\n"
                f"    opens to choose a build; leaving the pairing to a reader who\n"
                f"    knows to look elsewhere is what item 612 reported.",
                file=sys.stderr,
            )
            rc = 1

    # 3b-3e. The arm LATTICE. Its own function so the selftest can drive the
    #        SAME verdict over mutated manifests and mutated lane scripts --
    #        grading the shipped path rather than a restatement of it.
    lattice_rc, lattice_report, lattice_fail = check_lattice(manifest,
                                                             ROOT / RUNCI)
    for line in lattice_fail:
        print(line, file=sys.stderr)
    for line in lattice_report:
        print(line)
    if lattice_rc:
        rc = 1

    # 4. The prose.
    mentions, adjudicated, findings = scan(files, ARCHIVE_ARM)
    if adjudicated == 0:
        print(
            "  archive-arm FAIL: no sentence in the tree states the published\n"
            "    package's arm, so this gate adjudicated nothing. A population of\n"
            "    zero is not a pass.",
            file=sys.stderr,
        )
        rc = 1
    for finding in findings:
        print(f"  archive-arm FAIL: {finding}", file=sys.stderr)
        rc = 1
    print(f"  archive-arm: pin {PIN}; upstream publishes `{ARCHIVE_ARM}`, "
          f"{CAPI_C_MANIFEST.split('/')[1]}'s default models `{default_arm}`")
    print(f"  archive-arm: {mentions} sentence(s) name the package, "
          f"{adjudicated} state its arm, {len(findings)} disagree")
    return rc


def cmd_derive(require: bool, ref: pathlib.Path, prefix: pathlib.Path) -> int:
    rc = 0
    reached = 0

    try:
        upstream = derive_from_upstream(ref)
    except (FileNotFoundError, ValueError) as exc:
        if require:
            print(f"  archive-arm FAIL — required, and upstream's workflow could not\n"
                  f"    be read: {exc}", file=sys.stderr)
            rc = 1
        else:
            print(f"  archive-arm SKIP — no zenoh-c source checkout at {ref} ({exc})")
        upstream = None
    if upstream is not None:
        reached += 1
        print(f"  archive-arm: upstream's release workflow builds the package "
              f"`{upstream}`")
        if upstream != ARCHIVE_ARM:
            print(f"  archive-arm FAIL: this file says `{ARCHIVE_ARM}` and upstream's\n"
                  f"    own release workflow says `{upstream}`. Upstream is the fact;\n"
                  f"    move ARCHIVE_ARM and re-run `--check` for the sentences.",
                  file=sys.stderr)
            rc = 1

    try:
        installed = derive_from_install(prefix)
    except FileNotFoundError as exc:
        if require:
            print(f"  archive-arm FAIL — required, and no oracle is installed at\n"
                  f"    {prefix}: {exc}", file=sys.stderr)
            rc = 1
        else:
            print(f"  archive-arm SKIP — no installed oracle at {prefix}")
        installed = None
    if installed is not None:
        reached += 1
        print(f"  archive-arm: the oracle installed at {prefix} is `{installed}`")
        if installed != ARCHIVE_ARM:
            print(f"  archive-arm FAIL: the oracle at {prefix} is `{installed}` and\n"
                  f"    the published package is `{ARCHIVE_ARM}`. Either that prefix\n"
                  f"    holds a source build rather than the package, or the package\n"
                  f"    moved; the lanes that compare wz against it assume the latter.",
                  file=sys.stderr)
            rc = 1

    if require and reached == 0:
        print("  archive-arm FAIL — required and NEITHER derivation ran.",
              file=sys.stderr)
        rc = 1
    return rc


# ── selftest ─────────────────────────────────────────────────────────────────

def cmd_selftest() -> int:
    """Fixtures written to a temporary tree, because this file is scanned.

    Each case is a shape a per-line or phrase-list implementation lets through.
    """
    passed = 0
    failed = 0

    def case(name: str, ok: bool) -> None:
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1
            print(f"  archive-arm selftest FAIL: {name}", file=sys.stderr)

    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)

        # The claim WRAPPED across two comment lines. A per-line scan sees
        # neither half as a claim.
        wrapped = d / "wrapped.rs"
        wrapped.write_text(
            "//! The published standalone archive is the\n"
            "//! no-unstable build.\n"
            "fn main() {}\n"
        )
        _, adj, findings = scan([wrapped], "unstable-shm")
        case("a wrapped stale claim is adjudicated", adj == 1)
        case("a wrapped stale claim is a finding", len(findings) == 1)

        # The same sentence, correct. It must PASS -- a gate that reds on the
        # right answer teaches nothing.
        good = d / "good.rs"
        good.write_text("//! The published archive is the `unstable-shm` build.\n")
        _, adj, findings = scan([good], "unstable-shm")
        case("the canonical form passes", adj == 1 and not findings)

        # A DIFFERENT arm id sitting next to the package.
        both = d / "both.sh"
        both.write_text(
            "# The published archive (`nounstable`) and the CI build\n"
            "# (`unstable-shm`) are different oracles.\n"
        )
        _, adj, findings = scan([both], "unstable-shm")
        case("the nearer arm id is the one judged", adj == 1 and len(findings) == 1)

        # The SAME two ids, the other way round: the package resolves to the
        # derived arm and the other id belongs to something else. This is the
        # shape a "names any other arm" rule got wrong, so it is a fixture.
        contrast = d / "contrast.rs"
        contrast.write_text(
            "//! That archive resolves as `unstable-shm`, so building from\n"
            "//! source is the only route to a `nounstable` oracle now.\n"
        )
        _, adj, findings = scan([contrast], "unstable-shm")
        case("a correct contrast passes", adj == 1 and not findings)

        # A REFUTATION, which is what removing the history escape had to keep
        # writable: the true id sits nearest and the refuted one follows.
        refute = d / "refute.md"
        refute.write_text(
            "The published archive is the `unstable-shm` build at every "
            "release measured, and was never `nounstable`.\n"
        )
        _, adj, findings = scan([refute], "unstable-shm")
        case("a refutation passes", adj == 1 and not findings)

        # A macro the arm does not carry. Driven with an arm that has an axis
        # OFF, because the shipped arm carries both and could never fail this.
        macro = d / "macro.md"
        macro.write_text(
            "The published archive is the `nounstable` build, "
            "carrying `Z_FEATURE_UNSTABLE_API`.\n"
        )
        _, adj, findings = scan([macro], "nounstable")
        case("a macro the arm lacks is a finding", adj == 1 and len(findings) == 1)

        # A version literal buys NOTHING. There is no history escape, and this
        # is the fixture that says so: the same stale claim, dated, still reds.
        dated = d / "dated.sh"
        dated.write_text(
            "# At 1.5.0 the published archive was the `nounstable` build.\n"
        )
        _, adj, findings = scan([dated], "unstable-shm")
        case("dating a stale claim does not excuse it",
             adj == 1 and len(findings) == 1)

        # Mentions the package, claims nothing. Not a subject.
        mention = d / "mention.sh"
        mention.write_text("# Fetch the release archive and unpack it.\n")
        mentions, adj, findings = scan([mention], "unstable-shm")
        case("a bare mention is not adjudicated", mentions == 1 and adj == 0)

        # A CODE line must not join the prose around it into one sentence.
        code = d / "code.yml"
        code.write_text(
            "# The published archive is the `unstable-shm` build.\n"
            "  key: zenoh-c-shm-cache\n"
            "# It is fetched once.\n"
        )
        _, adj, findings = scan([code], "unstable-shm")
        case("code does not join prose", adj == 1 and not findings)

        # The manifest reader walks the feature CLOSURE, not the literal list.
        man = d / "Cargo.toml"
        man.write_text(
            "[features]\n"
            'default = ["archive-arm"]\n'
            'archive-arm = ["zenoh-c-shared-memory"]\n'
            "zenoh-c-no-unstable-api = []\n"
            "zenoh-c-shared-memory = []\n"
            "\n[dependencies]\n"
        )
        case("the default arm follows the feature closure",
             manifest_default_arm(man) == "unstable-shm")
        man.write_text(
            "[features]\n"
            "zenoh-c-no-unstable-api = []\n"
            "zenoh-c-shared-memory = []\n"
            "\n[dependencies]\n"
        )
        case("an absent default is the bare arm",
             manifest_default_arm(man) == "unstable")

        # The arm-id tokeniser: `no-unstable` is not the `unstable` id, and
        # `unstable-shm` is not the `unstable` id either.
        case("`no-unstable` is not an arm id",
             set(ARM_ID_RE.findall("the no-unstable build")) == set())
        case("a bare adjective is not an arm id",
             set(ARM_ID_RE.findall("built without unstable")) == set())
        case("`unstable-shm` reads whole",
             set(ARM_ID_RE.findall("the `unstable-shm` build")) == {"unstable-shm"})

        # The axis inversion is a search over `arm_id`, so it cannot drift.
        case("arm_axes inverts arm_id",
             all(arm_id(unstable=arm_axes(n)["UNSTABLE_API"],
                        shm=arm_axes(n)["SHARED_MEMORY"]) == n
                 for n in ARMS))

        # Sentence splitting must not break a filename or a version.
        case("a filename is not a sentence end",
             len(sentences("Run install-zenoh-c.sh first. Then build.")) == 2)
        case("a version is not a sentence end",
             len(sentences("The pin is 1.10.0 today.")) == 1)

        # ── the lattice arms (item 616) ──────────────────────────────────
        #
        # Driven through `check_lattice`, the SAME function `--check` calls,
        # over mutated copies of the two files it reads. Each mutation is one
        # a round could plausibly make, and each case pins the phrase its own
        # arm produces -- a case that reds for a neighbour's reason is not a
        # control.
        good_manifest = (
            "[features]\n"
            "zenoh-c-no-unstable-api = []\n"
            "zenoh-c-shared-memory = []\n"
            "\n[dependencies]\n"
        )
        good_runci = (
            "_runci_build_capi_c_for_oracle() {\n"
            "    local capi_c_features=()\n"
            '    if ! grep -q UNSTABLE "$h"; then\n'
            "        capi_c_features+=(--features zenoh-c-no-unstable-api)\n"
            "    fi\n"
            '    if grep -q SHARED "$h"; then\n'
            "        capi_c_features+=(--features zenoh-c-shared-memory)\n"
            "    fi\n"
            "}\n"
            "layer_c1cc() {\n"
            "    cargo test -p wz-capi-c --quiet\n"
            "    cargo test -p wz-capi-c --features zenoh-c-shared-memory "
            "--quiet\n"
            "}\n"
        )

        def lattice(manifest_text: str, runci_text: str) -> tuple[int, str]:
            (d / "lat.toml").write_text(manifest_text)
            (d / "lat.sh").write_text(runci_text)
            code, _, failures = check_lattice(d / "lat.toml", d / "lat.sh")
            return code, "\n".join(failures)

        rc_ok, _ = lattice(good_manifest, good_runci)
        case("the shipped shape passes", rc_ok == 0)

        rc_bad, why = lattice(
            good_manifest.replace("[features]\n",
                                  '[features]\ndefault = ["zenoh-c-shared-memory"]\n'),
            good_runci)
        case("a default off the origin loses two arms",
             rc_bad == 1 and "out of ADDITIVE reach" in why
             and "`nounstable`" in why and "`unstable`" in why)

        rc_bad, why = lattice(
            good_manifest.replace("\n[dependencies]",
                                  "zenoh-c-something-else = []\n\n[dependencies]"),
            good_runci)
        case("an unclassified feature is refused",
             rc_bad == 1 and "does not classify" in why)

        rc_bad, why = lattice(good_manifest, good_runci.replace(
            "    cargo test -p wz-capi-c --features zenoh-c-shared-memory "
            "--quiet\n", ""))
        case("an unpriced divergence is refused",
             rc_bad == 1 and "no `cargo test -p wz-capi-c` leg" in why)

        # R2287 (item 624). The leg that pays the divergence has to RUN. A
        # commented-out one satisfied the first cut of this arm, which is the
        # vacuity that made the bill payable with a string.
        rc_bad, why = lattice(good_manifest, good_runci.replace(
            "    cargo test -p wz-capi-c --features zenoh-c-shared-memory "
            "--quiet\n",
            "    # cargo test -p wz-capi-c --features zenoh-c-shared-memory\n"))
        case("a COMMENTED-OUT leg does not pay the divergence",
             rc_bad == 1 and "no `cargo test -p wz-capi-c` leg" in why)

        rc_bad, why = lattice(good_manifest, good_runci.replace(
            "        capi_c_features+=(--features zenoh-c-shared-memory)\n", ""))
        case("a selector blind to an axis is refused",
             rc_bad == 1 and "never adds" in why)

        rc_bad, why = lattice(good_manifest, good_runci.replace(
            "    local capi_c_features=()\n",
            "    local capi_c_features=(--no-default-features)\n"))
        case("selecting an arm by subtraction is refused",
             rc_bad == 1 and "SUBTRACTION" in why)

        rc_bad, why = lattice(good_manifest, good_runci.replace(
            "_runci_build_capi_c_for_oracle() {", "_some_other_name() {"))
        case("a selector this gate cannot find is not a pass",
             rc_bad == 1 and "no function" in why)

        # The lattice itself, so the two derivations cannot drift apart.
        case("arm_features round-trips through arm_of",
             all(arm_of(arm_features(a)) == a for a in ARMS))
        case("the shipped default is the origin",
             arm_features("unstable") == set())

    print(f"  archive-arm selftest: {passed}/{passed + failed} arm(s) pass")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="the published zenoh-c package's arm")
    ap.add_argument("--arm", action="store_true",
                    help="print the published package's arm id and exit")
    ap.add_argument("--check", action="store_true",
                    help="adjudicate the tree's sentences (needs no external input)")
    ap.add_argument("--derive", action="store_true",
                    help="re-derive the fact from upstream and from the install")
    ap.add_argument("--require", action="store_true",
                    help="with --derive, an absent input is a FAIL rather than a SKIP")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--ref", default=None,
                    help="zenoh-c source checkout "
                         "(default $WZ_ZENOH_C_REF or ~/zenoh-c-ref)")
    ap.add_argument("--prefix", default=None,
                    help="install prefix (default $WZ_ZENOH_C_PREFIX or ~/.local)")
    args = ap.parse_args()

    if not (args.arm or args.check or args.derive or args.selftest):
        ap.error("one of --arm / --check / --derive / --selftest is required")

    rc = 0
    if args.arm:
        print(ARCHIVE_ARM)
    if args.selftest:
        rc |= cmd_selftest()
    if args.check:
        rc |= cmd_check()
    if args.derive:
        ref = pathlib.Path(args.ref or os.environ.get("WZ_ZENOH_C_REF")
                           or (pathlib.Path.home() / "zenoh-c-ref"))
        prefix = pathlib.Path(args.prefix or os.environ.get("WZ_ZENOH_C_PREFIX")
                              or (pathlib.Path.home() / ".local"))
        rc |= cmd_derive(args.require, ref, prefix)
    return rc


if __name__ == "__main__":
    sys.exit(main())
