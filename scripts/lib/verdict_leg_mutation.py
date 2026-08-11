#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y726 (N14) — SEVER EACH LEG OF THE VERDICT AND REQUIRE A TEST TO REDDEN.

WHAT THIS IS. The sufficient condition `verdict_reason_lint` cannot express.
That gate asks whether a test NAMES each `VerdictReason`; this one asks whether
any test DEPENDS on it. For each variant in turn, the `out.push(...)` that raises
it in `CaptureReport::reasons` is replaced by a statement with no effect, the
suite is run, and at least one test must fail. A leg no test misses is a leg that
can be deleted in silence.

WHY IT HAD TO EXIST. R311y715 ran exactly this sweep BY HAND and found nine of
the twenty-four guards in the old `is_complete` binding nothing. R311y725 built
the static gate and MEASURED thirteen of twenty-three variants named by no test
at all -- then bound all thirteen, most of them by turning an existing
`!is_complete()` witness into an assertion on `reasons()`. Neither round proved
the legs are load-bearing; both proved something weaker. The register carried the
gap as N14, and a hand-run sweep is not a gate.

WHAT A RESULT MEANS.

  * a mutant whose tests FAIL -- the leg is load-bearing. This is the pass.
  * a mutant whose tests PASS -- nothing in the suite depends on this leg. It
    can be deleted and no one will know.
  * a mutant that does not COMPILE -- proves NOTHING, and is reported as a
    failure of this tool rather than a finding about the code. A severing that
    cannot be expressed needs a human, and counting it as "red, therefore
    load-bearing" is exactly the false pass this gate exists to refuse.

WHY IT MUTATES THE TREE IN PLACE. The alternative is a copy, and the copy is
worse than it looks: this workspace's cargo root is `crates/` with path
dependencies reaching `../vendor/`, so a hermetic copy is most of the repository.
Instead the original bytes are held, every exit path restores them, and the
restore is verified BYTE FOR BYTE before this reports anything. A backup left
behind is a previous run that died, and the next run REFUSES rather than guessing
which of the two files on disk is the real one.

THE BASELINE IS CHECKED FIRST, and that is not a formality: over a red tree every
mutant is red and this gate would report every leg load-bearing while measuring
nothing. A population-of-zero green, arriving through the front door.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LINT = Path(__file__).resolve().parent / "verdict_reason_lint.py"

# The file the legs live in, and where its untouched bytes are held while a
# mutant is on disk.
SOURCE = Path("crates/wz-capture/src/report.rs")
BACKUP = Path("crates/target/verdict-mutation/report.rs.pristine")

# A build directory of this sweep's own, so twenty-three recompiles do not
# evict the tree's ordinary one.
TARGET_DIR = Path("crates/target/verdict-mutation/target")

# One leg, as `reasons()` raises it.
PUSH = re.compile(r"^(\s*)out\.push\(VerdictReason::(\w+)\);\s*$", re.M)

# How long one mutant's suite may take before this calls it hung. Generous --
# the point is to notice a mutant that never returns, not to police speed.
RUN_TIMEOUT_S = 900


def load_lint():
    """The static gate's parser, imported rather than rewritten.

    The population of legs must be the SAME population both gates check, and two
    parsers over one declaration is two chances to disagree about it.
    """
    spec = importlib.util.spec_from_file_location("verdict_reason_lint", LINT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def crate_of(rel_path: str) -> str | None:
    """The cargo package name owning `rel_path`, read from its own Cargo.toml."""
    at = (REPO_ROOT / rel_path).parent
    while at != REPO_ROOT and at != at.parent:
        manifest = at / "Cargo.toml"
        if manifest.is_file():
            hit = re.search(
                r"(?ms)^\[package\].*?^name\s*=\s*\"([^\"]+)\"",
                manifest.read_text(encoding="utf-8"),
            )
            if hit:
                return hit.group(1)
        at = at.parent
    return None


def run_suite(packages: list[str]) -> tuple[str, str]:
    """`(verdict, output)` where verdict is `green` / `red` / `uncompilable`.

    The three are told apart deliberately. `cargo test` exits non-zero for a
    failing test and for a source that does not build, and reading the second as
    the first would let this gate pass a leg on the strength of a syntax error.
    """
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(REPO_ROOT / TARGET_DIR)
    cmd = ["cargo", "test"]
    for p in packages:
        cmd += ["-p", p]
    try:
        done = subprocess.run(
            cmd,
            cwd=REPO_ROOT / "crates",
            env=env,
            capture_output=True,
            text=True,
            timeout=RUN_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return "hung", f"no result within {RUN_TIMEOUT_S}s"
    out = done.stdout + done.stderr
    # THE DISCRIMINATOR, and the first version of it was wrong in a way worth
    # recording: it read any line opening `error: ` as a build failure, and
    # `cargo test` prints `error: test failed, to rerun pass ...` for a FAILING
    # TEST. Every one of the twenty-three mutants was therefore reported
    # uncompilable. The gate failed closed, which is the right direction to be
    # wrong in, and it still measured nothing.
    #
    # `could not compile` is cargo's own words for a crate that did not build,
    # and it is printed for nothing else. Linking is separate and is not a
    # compile, so it is named separately rather than assumed to be covered.
    if "could not compile" in out or "error: linking with" in out:
        return "uncompilable", out
    if done.returncode == 0:
        return "green", out
    # A non-zero exit with no test report at all is neither a red test nor a
    # build failure -- a harness that could not start, a panic in a build
    # script. Reading it as `red` would credit the leg with a kill it did not
    # earn, which is the false pass this whole tool exists to refuse.
    if "test result:" not in out:
        return "unrun", out
    return "red", out


def failing_tests(output: str) -> list[str]:
    """The test names cargo listed under `failures:`, for the evidence line."""
    names: list[str] = []
    for block in re.findall(r"(?ms)^failures:\n(.*?)(?:\n\n|\Z)", output):
        for line in block.splitlines():
            line = line.strip()
            if line and not line.endswith(":") and " " not in line:
                names.append(line)
    return sorted(set(names))


def main() -> int:
    source_path = REPO_ROOT / SOURCE
    backup_path = REPO_ROOT / BACKUP
    if not source_path.is_file():
        print(
            f"verdict-leg mutation: FAIL — {SOURCE} is not there, so there are "
            "no legs to sever and this must not report OK.",
            file=sys.stderr,
        )
        return 1
    if backup_path.exists():
        print(
            f"verdict-leg mutation: FAIL — {BACKUP} exists, which means a "
            "previous run died with a MUTANT on disk. This tool will not guess "
            f"which copy is real. Compare it against {SOURCE}, restore by hand, "
            "delete the backup, and run again.",
            file=sys.stderr,
        )
        return 1

    pristine = source_path.read_text(encoding="utf-8")

    lint = load_lint()
    declared, _wire = lint.declared(pristine)
    pushes = PUSH.findall(pristine)
    raised = sorted({variant for _indent, variant in pushes})
    if not declared:
        print(
            "verdict-leg mutation: FAIL — the enum declaration did not parse. "
            "The population is read from it and a sweep with no population "
            "measures nothing.",
            file=sys.stderr,
        )
        return 1
    missing = sorted(set(declared) - set(raised))
    if missing:
        # A variant nothing raises is a leg no capture can reach: severing it
        # would change nothing, and reporting that as "not load-bearing" would
        # name the wrong defect.
        print("verdict-leg mutation: FAIL", file=sys.stderr)
        for v in missing:
            print(
                f"  `VerdictReason::{v}` is declared and `reasons()` never "
                "pushes it — no capture can raise this leg at all",
                file=sys.stderr,
            )
        return 1

    # Which packages to run. DERIVED from where the bindings actually are, so a
    # binding that moves to a new crate brings that crate into the sweep without
    # anyone editing a list here.
    bound, _tests, _files = lint.test_bindings(REPO_ROOT)
    crates_for: dict[str, list[str]] = {}
    for variant, sites in bound.items():
        crates_for[variant] = sorted(
            {crate for site in sites if (crate := crate_of(site.split("::", 1)[0]))}
        )
    packages = sorted({c for cs in crates_for.values() for c in cs})
    if not packages:
        print(
            "verdict-leg mutation: FAIL — no crate owns any binding, so the "
            "sweep would run no tests at all.",
            file=sys.stderr,
        )
        return 1

    backup_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, backup_path)
    survivors: list[str] = []
    broken: list[tuple[str, str]] = []
    evidence: dict[str, list[str]] = {}
    try:
        print(
            f"verdict-leg mutation: {len(raised)} leg(s), suite = "
            f"{' '.join(packages)}",
            flush=True,
        )
        verdict, output = run_suite(packages)
        if verdict != "green":
            print(
                "verdict-leg mutation: FAIL — the UNMUTATED tree is not green "
                f"({verdict}). Over a red tree every mutant is red and this "
                "sweep would report every leg load-bearing while measuring "
                "nothing.\n" + output[-4000:],
                file=sys.stderr,
            )
            return 1
        # The baseline also PROVES the discriminator: a green here means the
        # unmutated suite was run and read as green, so a later `red` is this
        # tool telling two states apart rather than always saying one of them.
        if "test result:" not in output:
            print(
                "verdict-leg mutation: FAIL — the baseline run produced no "
                "`test result:` line, so nothing was actually run and every "
                "verdict below would be about an empty suite.",
                file=sys.stderr,
            )
            return 1
        print("  baseline green", flush=True)

        for variant in raised:
            mutant = PUSH.sub(
                lambda m: (
                    f"{m.group(1)}let _ = VerdictReason::{m.group(2)};"
                    if m.group(2) == variant
                    else m.group(0)
                ),
                pristine,
            )
            if mutant == pristine:
                broken.append((variant, "the severing produced no change"))
                continue
            source_path.write_text(mutant, encoding="utf-8")
            # The crates whose tests NAME this leg go first. A kill found in a
            # subset is a kill: running fewer tests can only make a mutant
            # harder to catch, never easier, so a red here is proof and a green
            # here is not yet an answer. Twenty of the twenty-three legs are
            # named only inside `wz-capture`, and asking about those without
            # rebuilding the reader is most of this sweep's wall clock.
            narrow = crates_for.get(variant) or packages
            verdict, output = run_suite(narrow)
            if verdict == "green" and narrow != packages:
                # ESCALATION, and it is what keeps the narrowing honest: a leg
                # that survives its own crate might still be depended on by a
                # test that never names it, and calling that a survivor would
                # be this tool reporting a defect it manufactured.
                verdict, output = run_suite(packages)
            if verdict == "uncompilable":
                broken.append((variant, f"the mutant does not compile\n{output[-1500:]}"))
            elif verdict in ("hung", "unrun"):
                broken.append((variant, f"{verdict}: {output[-1500:]}"))
            elif verdict == "green":
                survivors.append(variant)
                print(f"  {variant}: SURVIVED", flush=True)
            else:
                names = failing_tests(output)
                evidence[variant] = names
                print(
                    f"  {variant}: killed by {len(names)} test(s) in "
                    f"{' '.join(narrow)}" + (f" (e.g. {names[0]})" if names else ""),
                    flush=True,
                )
    finally:
        source_path.write_text(pristine, encoding="utf-8")
        restored = source_path.read_text(encoding="utf-8")
        if restored != pristine:
            print(
                f"verdict-leg mutation: FAIL — {SOURCE} did not restore to its "
                "original bytes. The backup is still at "
                f"{BACKUP}; restore it by hand.",
                file=sys.stderr,
            )
            return 1
        backup_path.unlink(missing_ok=True)

    if broken:
        print("verdict-leg mutation: FAIL", file=sys.stderr)
        for variant, why in broken:
            print(f"  `VerdictReason::{variant}`: {why}", file=sys.stderr)
        print(
            "\nA mutant that does not build proves nothing about the leg. This "
            "is a\nfailure of the SWEEP, not a finding about the code: the "
            "severing has to be\nexpressible before the question can be asked.",
            file=sys.stderr,
        )
        return 1
    if survivors:
        print("verdict-leg mutation: FAIL", file=sys.stderr)
        for variant in survivors:
            print(
                f"  `VerdictReason::{variant}` SURVIVED — every test passed "
                "with this leg severed, so nothing in the suite depends on it",
                file=sys.stderr,
            )
        print(
            "\nA surviving leg can be deleted and no one will know. R311y715 "
            "measured nine\nsuch guards at once. Bind it with a fixture that "
            "raises this reason and asserts\nit BY NAME -- "
            "`reasons() == vec![VerdictReason::X]` where the fixture can be "
            "isolated.",
            file=sys.stderr,
        )
        return 1

    least = min(len(v) for v in evidence.values()) if evidence else 0
    print(
        f"verdict-leg mutation: OK ({len(raised)} leg(s) severed, every one "
        f"killed by at least {least} test(s); suite = {' '.join(packages)})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
