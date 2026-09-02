#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2281 (no register item) — TWO ORACLES AT THE SAME ARM MEASURE ONE THING TWICE.

## The citation

This answers the numeric open-debt register's item 617, which lives in the
operator's notes rather than in the store, so `gate_provenance_lint`'s item
grammar cannot resolve it; `zenoh_c_archive_arm.py` set the precedent for
declaring the escape hatch on the first line and naming the item in the body.

## The defect

`Z_FEATURE_UNSTABLE_API` and `Z_FEATURE_SHARED_MEMORY` are independent axes, so
"the installed zenoh-c" names one of FOUR builds (`zenoh-c-oracle-arm.sh`).
Layer C1ce exists to measure wz against a SECOND arm, and R311y541 wrote its
rationale on the reading that the installed oracle declared NEITHER axis. R2278
measured upstream's published archive and it is `unstable-shm` — both axes —
which is the arm `install-zenoh-c-shm.sh` builds. So the second oracle was the
first oracle's arm, built a second way, and no sentence in the tree could have
said so: the arm of a prefix was nowhere derived from the tree, only from a
directory that happened to be on one machine.

Running `zenoh-c-oracle-arm.sh` on the two prefixes answers it for THIS machine.
That is not enough for a gate — a clone with no oracle installed would then
check nothing, and "nothing installed" would read as "no duplicate". So the arm
is derived from the INSTALLERS instead, which are in the tree on every clone.

## What is derived, and from where

  consumers   every `WZ_ZENOH_C*PREFIX:-<default>` in a tracked shell file. That
              expansion is how a lane, a check script and the installers all
              name an oracle, so the set of oracle LOCATIONS is the set of those
              defaults. A hand-written list of lanes would not have this
              property: it would keep passing when a lane is added.

  installers  the same expansion inside `scripts/install-zenoh-c*.sh` gives each
              installer's own default prefix, and what it installs there is read
              from the script: `install-zenoh-c.sh` unpacks upstream's published
              archive, whose arm is `zenoh_c_archive_arm`'s one derived fact;
              the wrappers `exec` `install-zenoh-c-arm.sh <arm> "$PREFIX"` and
              the arm is that literal argument. `install-zenoh-c-arm.sh` itself
              is parametric — `target/zenoh-c-<arm>` — which is a RULE, not a
              row, and is applied as one.

## The four refusals

  1. no consumer prefix could be derived at all -> the scan broke, not the tree.
  2. a consumer names a prefix no installer provisions -> its arm is a guess,
     which is the defect `zenoh-c-oracle-arm.sh` was split out to remove.
  3. two DISTINCT prefixes carry the SAME arm -> one of them buys nothing. This
     is item 617's own condition, stated as the item states it.
  4. an installer owns a fixed prefix NO consumer names -> minutes of CI build
     for an oracle nothing reads. The mirror of (3), and it is not hypothetical:
     re-aiming the second oracle away from `unstable-shm` is what left
     `install-zenoh-c-shm.sh` with no reader, and without this arm the tree
     would have kept provisioning it. `install-zenoh-c-arm.sh` is exempt by
     construction rather than by name -- its prefix is a parameter, so it
     declares no fixed one and cannot be orphaned.

Prefixes, not lanes, are the subject of (3) on purpose. Several lanes share
`~/.local` deliberately (C1cc and C1cd differ in TOPOLOGY, not in arm), and a
rule over lanes would call that a duplicate. Two separate INSTALLS of one arm is
the waste; two lanes reading one install is not.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(REPO_ROOT / "scripts" / "lib"))
import zenoh_c_archive_arm as _archive  # noqa: E402

ARMS = _archive.ARMS

# `${WZ_ZENOH_C_ANYTHING_PREFIX:-<default>}`. The default runs to the closing
# brace; a quote would end a shell word, so neither can appear inside it.
PREFIX_DEFAULT_RE = re.compile(r"WZ_ZENOH_C[A-Z_]*PREFIX:-([^}\"']+)")

# `exec bash "$ROOT/scripts/install-zenoh-c-arm.sh" <arm> "$PREFIX"` — the arm a
# wrapper installs is its first argument, read as a literal.
ARM_WRAPPER_RE = re.compile(
    r"install-zenoh-c-arm\.sh\"?\s+([a-z-]+)\s")

# `install-zenoh-c-arm.sh`'s own parametric prefix rule.
PARAMETRIC_RE = re.compile(r"^target/zenoh-c-(" + "|".join(ARMS) + r")$")


def normalise(expr: str) -> str:
    """A prefix expression as a stable name: `~/x` for HOME, repo-relative else."""
    e = expr.strip()
    e = re.sub(r"^\$\{?HOME\}?/", "~/", e)
    e = re.sub(r"^\$\{?(ROOT|repo_root)\}?/", "", e)
    return e.rstrip("/")


def scan_files() -> dict[str, str]:
    """Tracked shell files that could name an oracle prefix, path -> text.

    From `git ls-files`, so a file that is not in the commit cannot supply a
    prefix and cannot hide one either.
    """
    out = subprocess.run(["git", "-C", str(REPO_ROOT), "ls-files", "*.sh"],
                         capture_output=True, text=True, check=True).stdout
    files = {}
    for rel in out.split():
        p = REPO_ROOT / rel
        try:
            files[rel] = p.read_text()
        except (OSError, UnicodeDecodeError):
            continue
    return files


def consumer_prefixes(files: dict[str, str]) -> dict[str, list[str]]:
    """Normalised prefix -> the files naming it (installers excluded)."""
    found: dict[str, list[str]] = {}
    for rel, text in sorted(files.items()):
        if Path(rel).name.startswith("install-zenoh-c"):
            continue
        for m in PREFIX_DEFAULT_RE.finditer(text):
            found.setdefault(normalise(m.group(1)), []).append(rel)
    return found


def installer_arms(files: dict[str, str], published: str) -> dict[str, str]:
    """Normalised prefix -> the arm the installer that owns it puts there."""
    arms: dict[str, str] = {}
    for rel, text in sorted(files.items()):
        name = Path(rel).name
        if not name.startswith("install-zenoh-c"):
            continue
        defaults = [normalise(m.group(1)) for m in PREFIX_DEFAULT_RE.finditer(text)]
        if not defaults:
            continue
        wrapped = ARM_WRAPPER_RE.search(text)
        for prefix in defaults:
            if wrapped:
                # A wrapper: it names the arm it delegates for.
                arms[prefix] = wrapped.group(1)
            else:
                # The archive installer. Its arm is upstream's decision, and
                # `zenoh_c_archive_arm` is the one place that derives it.
                arms[prefix] = published
    return arms


def resolve(prefix: str, installed: dict[str, str]) -> str | None:
    """The arm at `prefix`: an installer's row, or the parametric rule."""
    if prefix in installed:
        return installed[prefix]
    m = PARAMETRIC_RE.match(prefix)
    return m.group(1) if m else None


def check(files: dict[str, str], published: str) -> tuple[bool, list[str]]:
    lines: list[str] = []
    ok = True

    consumers = consumer_prefixes(files)
    if not consumers:
        return False, ["oracle-arms FAIL: no `WZ_ZENOH_C*PREFIX:-` default was "
                       "found in any tracked shell file. That is the scan "
                       "having stopped scanning, not the tree having no "
                       "oracle -- a population of zero is not a pass."]

    installed = installer_arms(files, published)
    if not installed:
        return False, ["oracle-arms FAIL: no installer declared a prefix, so "
                       "no consumer's arm can be derived from the tree."]

    by_arm: dict[str, list[str]] = {}
    for prefix in sorted(consumers):
        arm = resolve(prefix, installed)
        if arm is None:
            ok = False
            lines.append(
                f"oracle-arms FAIL: `{prefix}` is measured by "
                f"{', '.join(sorted(set(consumers[prefix])))} and NO installer "
                f"in this tree provisions it, so its arm is a guess. Either "
                f"provision it (scripts/install-zenoh-c-arm.sh <arm> "
                f"{prefix}) or point the consumer at a prefix that is.")
            continue
        by_arm.setdefault(arm, []).append(prefix)
        lines.append(f"  oracle-arms: {prefix} -> {arm} "
                     f"({', '.join(sorted(set(consumers[prefix])))})")

    for prefix in sorted(set(installed) - set(consumers)):
        ok = False
        lines.append(
            f"oracle-arms FAIL: an installer owns `{prefix}` (arm "
            f"`{installed[prefix]}`) and NO consumer names it. Provisioning it "
            f"costs a build and buys nothing readable. Point a lane at it, or "
            f"retire the installer that owns it.")

    for arm, prefixes in sorted(by_arm.items()):
        if len(prefixes) > 1:
            ok = False
            lines.append(
                f"oracle-arms FAIL: {len(prefixes)} DISTINCT oracle prefixes "
                f"carry the same arm `{arm}` -- {', '.join(sorted(prefixes))}. "
                f"One of them buys nothing: every leg run against it could be "
                f"run against the other. Re-aim one at an arm no other prefix "
                f"carries, or retire it together with its consumers.")

    lines.append(f"  oracle-arms: {len(consumers)} prefix(es), "
                 f"{len(by_arm)} of {len(ARMS)} arm(s) covered "
                 f"({', '.join(sorted(by_arm)) or 'none'})")
    return ok, lines


# ─── selftest ───────────────────────────────────────────────────────────────
#
# Each fixture is a shape the check has to answer differently, and two of them
# are shapes this gate's own subject wore: a second oracle built at the arm the
# first one already is (the whole of item 617), and a consumer pointed at a
# prefix nothing provisions (which is how an arm becomes a guess).

_INSTALLER_ARCHIVE = 'PREFIX="${WZ_ZENOH_C_PREFIX:-$HOME/.local}"\n'
_INSTALLER_SHM = (
    'PREFIX="${WZ_ZENOH_C_SHM_PREFIX:-$ROOT/target/zenoh-c-shm}"\n'
    'exec bash "$ROOT/scripts/install-zenoh-c-arm.sh" unstable-shm "$PREFIX"\n')
_INSTALLER_UNSTABLE = (
    'PREFIX="${WZ_ZENOH_C_UNSTABLE_PREFIX:-$ROOT/target/zenoh-c-unstable}"\n'
    'exec bash "$ROOT/scripts/install-zenoh-c-arm.sh" unstable "$PREFIX"\n')

_CASES = [
    ("two prefixes, the SAME arm", False, {
        "scripts/install-zenoh-c.sh": _INSTALLER_ARCHIVE,
        "scripts/install-zenoh-c-shm.sh": _INSTALLER_SHM,
        "scripts/run-ci.sh": 'a="${WZ_ZENOH_C_PREFIX:-$HOME/.local}"\n'
                             'b="${WZ_ZENOH_C_SHM_PREFIX:-$repo_root/target/zenoh-c-shm}"\n',
    }),
    ("two prefixes, DIFFERENT arms", True, {
        "scripts/install-zenoh-c.sh": _INSTALLER_ARCHIVE,
        "scripts/install-zenoh-c-unstable.sh": _INSTALLER_UNSTABLE,
        "scripts/run-ci.sh": 'a="${WZ_ZENOH_C_PREFIX:-$HOME/.local}"\n'
                             'b="${WZ_ZENOH_C_UNSTABLE_PREFIX:-$repo_root/target/zenoh-c-unstable}"\n',
    }),
    ("a consumer prefix nothing provisions", False, {
        "scripts/install-zenoh-c.sh": _INSTALLER_ARCHIVE,
        "scripts/run-ci.sh": 'a="${WZ_ZENOH_C_PREFIX:-$HOME/.local}"\n'
                             'b="${WZ_ZENOH_C_ODD_PREFIX:-$repo_root/target/zenoh-c-mystery}"\n',
    }),
    ("the parametric rule provisions it", True, {
        "scripts/install-zenoh-c.sh": _INSTALLER_ARCHIVE,
        "scripts/run-ci.sh": 'a="${WZ_ZENOH_C_PREFIX:-$HOME/.local}"\n'
                             'b="${WZ_ZENOH_C_NS_PREFIX:-$repo_root/target/zenoh-c-nounstable}"\n',
    }),
    ("no consumer at all", False, {
        "scripts/install-zenoh-c.sh": _INSTALLER_ARCHIVE,
        "scripts/run-ci.sh": 'nothing here names an oracle\n',
    }),
    ("an installer nothing reads", False, {
        "scripts/install-zenoh-c.sh": _INSTALLER_ARCHIVE,
        "scripts/install-zenoh-c-shm.sh": _INSTALLER_SHM,
        "scripts/run-ci.sh": 'a="${WZ_ZENOH_C_PREFIX:-$HOME/.local}"\n',
    }),
]


def selftest() -> bool:
    ok = True
    for name, want, files in _CASES:
        got, lines = check(files, "unstable-shm")
        if got != want:
            ok = False
            print(f"  oracle-arms SELFTEST `{name}`: got {got}, expected {want}",
                  file=sys.stderr)
            for ln in lines:
                print(f"      {ln}", file=sys.stderr)
    if ok:
        print(f"  oracle-arms: selftest passed ({len(_CASES)} cases, both verdicts)")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="derive every oracle prefix's arm and refuse duplicates")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest and not selftest():
        return 1
    if args.check:
        ok, lines = check(scan_files(), _archive.ARCHIVE_ARM)
        for ln in lines:
            print(ln if ln.startswith("  ") else ln, file=None if ok else sys.stderr)
        if not ok:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
