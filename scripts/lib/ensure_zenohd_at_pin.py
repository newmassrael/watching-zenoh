#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
r"""R2647 (no register item) — a RESTORED oracle is trusted without being read.

The citation is `no register item` in the sense `debt_plane_census.py` uses, and
for the same reason its two neighbours here give: the item this answers for —
758 — lives in the agent-memory register, which has no store id for
`gate_provenance_lint.py` to resolve. The item is named in prose below.

## The defect, measured

`.github/workflows/ci.yml` provisions each zenohd oracle in three steps:

    - uses: actions/cache@v4      path: target/zenohd-unixpipe
                                  key:  zenohd-unixpipe-1.10.1-ubuntu-22.04-<hash>
    - run: bash scripts/build-zenohd.sh        if: cache-hit != 'true'
    - run: test -x target/zenohd-unixpipe/zenohd   # presence, nothing more

The build runs ONLY on a cache miss, and the step after it asks whether a file
EXISTS. Nothing asks what it IS. The key merely NAMES `1.10.1`; it is a promise
made before the build, not a reading of what the build produced.

So an entry cached under that key whose binary was never 1.10.1 is restored
for ever: the build never runs, and `build-zenohd.sh`'s own version assert
(@ `checkout version $checkout_version != pinned ZENOHD_VERSION`) cannot fire
because it is inside the build. MEASURED on runs 34977306103 and 34996365804,
job `cross-impl proof lanes`, step `Layer Z — zenohd (zenoh-full) interop`:

    oracle-pin-gate: MATCH  target/zenohd            -- v1.10.1
    oracle-pin-gate: STALE  target/zenohd-unixpipe   -- binary says 1211779c
    oracle-pin-gate: STALE  target/zenohd-vsock      -- binary says 1211779c
    unreached: reached 1 of 78 guarded leg(s); 77 did not run

`1211779c` is a commit hash, which is what a zenohd built from an untagged
checkout reports — `oracle_pin_gate.VERSION_RE`'s comment names exactly that
case. One poisoned cache entry per variant has been hiding 77 of 78 legs of the
only lane that grades wz against the canonical Rust implementation.

## What this REFUTES, written down rather than dropped

The standing diagnosis (agent-memory `project_hosted_red_layer_z_oracle_pin`)
was "`build-zenohd.sh` prefers a cargo-git checkout over the pinned-tag clone,
so the variants build off-pin". Re-measured, that cannot produce this symptom:
the script asserts the SELECTED source's version against the pin and exits 1 on
a mismatch, so an off-pin source fails the build loudly instead of shipping a
divergent oracle. The source selection is not the defect; trusting a restore
without reading it is.

## Why this is not `oracle_pin_gate.py`

That gate GRADES; this one REPAIRS, and the two must not be one thing. The gate
is a lane step — run-ci Layer C0 runs it unarmed and Layer Z `--require`s it —
so by the time it speaks, the lane it guards is already failing. A grader that
also rebuilt would make "is this oracle at the pin" unanswerable without side
effects, which is the property every control in this tree depends on.

It does, however, DERIVE FROM THE GATE rather than beside it: the population,
the pin and the per-oracle classification are `oracle_pin_gate`'s own functions.
Asking the grader what it grades is what keeps the repairer from fixing a set
the grader does not judge — and the set equality is ASSERTED below, so the two
cannot drift apart silently.

## NOT round-fed, and that was MEASURED rather than assumed

`round_fed_gate_reach.py` does not carry this module, and the reason is the same
one that keeps `oracle_pin_gate` out: a round-fed gate is one whose subject is
what a round CHANGES, and these two answer about BUILD OUTPUT — an untracked
binary a push never writes. Checked by running that checker's own
`round_fed(...)` over this file's source: the population is 92 with and without
it. So this gate needs no `.githooks/pre-push` row and no DEFERRED row, and a
later round should not add one to be tidy — a deferral that nobody is paying
for claims a cost that is not real, which is the one thing that table forbids.

What DOES belong in a lane is `--selftest` and `--check`, beside
`oracle_pin_gate`'s two in the same block: both read files only, cost
milliseconds, and are machine-independent. ⛔ The DEFAULT mode must never run
there — it builds.

## The population, derived twice and required to agree

Each oracle's build is selected by an environment variable, and the pairing is
structural in `build-zenohd.sh`: the `INSTALL_DIR="$ROOT/target/…"` assignment
that follows an `if/elif [[ "${ZENOHD_X:-0}" -eq 1 ]]; then` line belongs to
that variable, and the one that follows no such line is the DEFAULT oracle,
built with no variant variable at all. That derivation is run here and its
directory set is asserted equal to `oracle_pin_gate.population()`. A fifth
variant added to that script is therefore covered the day it is added, and a
change that breaks the pairing fails loudly rather than rebuilding the wrong
oracle.

A population of zero is a HARD FAIL, on both derivations.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import oracle_pin_gate as g  # noqa: E402

#: An `if`/`elif` line selecting a variant, capturing its environment variable.
GUARD_RE = re.compile(r'^\s*(?:el)?if\s+\[\[\s*"\$\{(ZENOHD_[A-Z0-9_]+):-0\}"\s*-eq\s*1\s*\]\]')
#: An install-directory assignment, capturing the `target/…` path.
INSTALL_RE = re.compile(r'^\s*INSTALL_DIR="\$ROOT/(target/[^"]+)"')


def variant_envs(script_text: str) -> dict[str, str | None]:
    """`{install dir: selecting env var or None}` for every oracle.

    The pairing is POSITIONAL because that is how the script expresses it: the
    assignment sits inside the `then` branch of the guard directly above it.
    A `None` means the default oracle, which no variable selects.
    """
    pairs: dict[str, str | None] = {}
    previous_guard: str | None = None
    for line in script_text.splitlines():
        install = INSTALL_RE.match(line)
        if install:
            pairs.setdefault(install.group(1), previous_guard)
            previous_guard = None
            continue
        guard = GUARD_RE.match(line)
        if guard:
            previous_guard = guard.group(1)
        elif line.strip() and not line.lstrip().startswith("#"):
            # Any other CODE line ends a guard's reach: only the assignment
            # immediately inside the branch is that variant's.
            previous_guard = None
    return pairs


def decide(finding_kind: str) -> bool:
    """Does this oracle need building? Every class except MATCH does.

    ABSENT is included deliberately: in CI the caller names only the oracles
    that job provisions, so "absent" there means the restore produced nothing
    and the build must run — which is what the `cache-hit` condition used to
    express and expressed only by accident.
    """
    return finding_kind != g.MATCH


def build_command(env_var: str | None) -> tuple[list[str], dict[str, str]]:
    env = {"ZENOHD_ALLOW_CLONE": "1"}
    if env_var:
        env[env_var] = "1"
    return (["bash", str(g.BUILD_SCRIPT)], env)


def resolve(script_text: str) -> dict[str, str | None]:
    pairs = variant_envs(script_text)
    graded = g.population(script_text)
    if not pairs or not graded:
        raise SystemExit(
            "ensure-zenohd-at-pin: FAIL -- derived no oracle at all "
            f"(pairing {len(pairs)}, gate {len(graded)}). A repairer with no "
            "subject must not report success."
        )
    if set(pairs) != set(graded):
        raise SystemExit(
            "ensure-zenohd-at-pin: FAIL -- the pairing and the gate disagree "
            f"about the oracle set: pairing={sorted(pairs)} gate={sorted(graded)}. "
            "Repairing a set the grader does not judge is how the two drift."
        )
    return pairs


#: Fixture text is BUILT, never pasted: a literal copy of the real script here
#: would be a second statement of the thing this file derives, and it would go
#: stale exactly when the derivation needed testing most.
def _fixture(variants: list[str], with_default: bool = True) -> str:
    lines = ['ZENOHD_VERSION="${ZENOHD_VERSION:-9.9.9}"', ""]
    if with_default:
        lines.append('INSTALL_DIR="$ROOT/target/zenohd"')
    for i, name in enumerate(variants):
        keyword = "if" if i == 0 else "elif"
        lines.append('%s [[ "${ZENOHD_%s:-0}" -eq 1 ]]; then' % (keyword, name))
        lines.append('    INSTALL_DIR="$ROOT/target/zenohd-%s"' % name.lower())
    if variants:
        lines.append("fi")
    return "\n".join(lines) + "\n"


def selftest() -> int:
    # ── the decision table, which is the whole behaviour ────────────────
    # Only MATCH means "leave it alone". The other three all mean the oracle
    # this job is about to use is not the one the tree pins.
    for verdict, expected in (
        (g.MATCH, False),
        (g.STALE, True),
        (g.ABSENT, True),
        (g.UNREADABLE, True),
    ):
        if decide(verdict) is not expected:
            print("selftest FAIL: decide(%s) is not %s" % (verdict, expected))
            return 1

    # ── the pairing derives the DEFAULT as env-less and each variant by name ──
    text = _fixture(["UNIXPIPE", "VSOCK", "SHM"])
    pairs = variant_envs(text)
    want = {
        "target/zenohd": None,
        "target/zenohd-unixpipe": "ZENOHD_UNIXPIPE",
        "target/zenohd-vsock": "ZENOHD_VSOCK",
        "target/zenohd-shm": "ZENOHD_SHM",
    }
    if pairs != want:
        print("selftest FAIL: pairing %s != %s" % (pairs, want))
        return 1

    # ── a FIFTH variant is covered with no edit here ───────────────────
    grown = variant_envs(_fixture(["UNIXPIPE", "VSOCK", "SHM", "QUIC"]))
    if grown.get("target/zenohd-quic") != "ZENOHD_QUIC":
        print("selftest FAIL: a new variant was not derived: %s" % grown)
        return 1

    # ── the build command carries the variant AND the clone opt-in ─────
    argv, env = build_command("ZENOHD_UNIXPIPE")
    if env.get("ZENOHD_UNIXPIPE") != "1" or env.get("ZENOHD_ALLOW_CLONE") != "1":
        print("selftest FAIL: build env is %s" % env)
        return 1
    if "ZENOHD_UNIXPIPE" in build_command(None)[1]:
        print("selftest FAIL: the default oracle must carry no variant variable")
        return 1
    if not argv or not argv[0].endswith("bash"):
        print("selftest FAIL: build argv is %s" % argv)
        return 1

    # ── a population of zero is a HARD FAIL, on either derivation ──────
    try:
        resolve(_fixture([], with_default=False))
    except SystemExit as exc:
        if "derived no oracle" not in str(exc):
            print("selftest FAIL: empty population raised the wrong error: %s" % exc)
            return 1
    else:
        print("selftest FAIL: an empty population did not fail")
        return 1

    # ── the two derivations must AGREE, and disagreement is loud ───────
    # Damage the gate's own regex so it sees one oracle fewer than the pairing
    # does; the repairer must refuse rather than fix a set nobody grades.
    saved = g.INSTALL_DIR_RE
    try:
        g.INSTALL_DIR_RE = re.compile(r'^\s*INSTALL_DIR="\$ROOT/(target/zenohd)"', re.M)
        try:
            resolve(text)
        except SystemExit as exc:
            if "disagree" not in str(exc):
                print("selftest FAIL: drift raised the wrong error: %s" % exc)
                return 1
        else:
            print("selftest FAIL: a pairing/gate disagreement did not fail")
            return 1
    finally:
        g.INSTALL_DIR_RE = saved

    print("ensure-zenohd-at-pin: selftest OK (6 derivations driven)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="ensure_zenohd_at_pin.py",
        description="Rebuild any named zenohd oracle that does not answer at the pin.",
    )
    ap.add_argument("roots", nargs="*", help="oracle dirs, e.g. target/zenohd-unixpipe")
    ap.add_argument("--plan", action="store_true", help="print decisions, build nothing")
    ap.add_argument("--list", action="store_true", help="print `dir<TAB>env` pairs and exit")
    ap.add_argument("--selftest", action="store_true", help="drive the decisions against fixtures")
    ap.add_argument(
        "--check",
        action="store_true",
        help=(
            "grade the PAIRING against the live build script and print the population. "
            "Machine-independent: it reads no binary, so a host with no oracle built "
            "grades it exactly as a host with four."
        ),
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    script_text = g.BUILD_SCRIPT.read_text(encoding="utf-8")
    pairs = resolve(script_text)
    pinned = g.pin(script_text)

    if args.list:
        for directory, env_var in pairs.items():
            print("%s\t%s" % (directory, env_var or "-"))
        return 0

    if args.check:
        # The measurement is PRINTED, not merely exited on: a silent `rc=0`
        # cannot be told apart from a gate that never ran.
        variants = sum(1 for env_var in pairs.values() if env_var)
        print(
            "  ensure-zenohd-at-pin: %d oracle(s) paired to their build variable "
            "-- %d default, %d variant; pin %s; the set agrees with oracle_pin_gate"
            % (len(pairs), len(pairs) - variants, variants, pinned)
        )
        for directory, env_var in pairs.items():
            print("    %-24s <- %s" % (directory, env_var or "(no variant variable)"))
        return 0

    roots = args.roots or list(pairs)
    unknown = [r for r in roots if r not in pairs]
    if unknown:
        raise SystemExit(
            "ensure-zenohd-at-pin: FAIL -- %s is not an oracle this tree builds; "
            "known: %s" % (", ".join(unknown), ", ".join(pairs))
        )

    rc = 0
    for rel in roots:
        finding = g.inspect(g.ROOT, rel, pinned)
        if not decide(finding.verdict):
            print("ensure-zenohd-at-pin: OK       %s -- %s" % (rel, finding.detail))
            continue
        argv, env = build_command(pairs[rel])
        print(
            "ensure-zenohd-at-pin: REBUILD  %s -- %s (%s)"
            % (rel, finding.detail, " ".join("%s=%s" % kv for kv in sorted(env.items())))
        )
        if args.plan:
            continue
        merged = dict(os.environ)
        merged.update(env)
        built = subprocess.run(argv, cwd=str(g.ROOT), env=merged).returncode
        if built != 0:
            print("ensure-zenohd-at-pin: FAIL     %s -- build exited %d" % (rel, built))
            rc = 1
            continue
        after = g.inspect(g.ROOT, rel, pinned)
        if decide(after.verdict):
            print(
                "ensure-zenohd-at-pin: FAIL     %s -- still %s after a rebuild: %s"
                % (rel, after.verdict, after.detail)
            )
            rc = 1
        else:
            print("ensure-zenohd-at-pin: REPAIRED %s -- %s" % (rel, after.detail))
    return rc


if __name__ == "__main__":
    sys.exit(main())
