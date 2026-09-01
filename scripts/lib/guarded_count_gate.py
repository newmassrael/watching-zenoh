#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2167 (no register item) — RUN the count guards a static read cannot resolve,
when the push moves the test set they count.

The citation is `no register item` for `debt_plane_census.py`'s reason: the
class this answers for has never had a store row. It lives in `run-ci.sh`
prose, which is precisely the arrangement that failed.

## The defect, measured three times

`count_guard_lint.py` (R311y569, widened R2137) checks a count guard by READING
both sides: `N` in `run-ci.sh`, and the `#[test]` census of the file the guard
names. That works only when the test set does not depend on the build
configuration, so the lint declares the rest OUT OF SCOPE — 189 of 291 guards
as of this round — and says why for each. That list is honest and it is also a
hole: a guard nothing checks statically is a guard nothing checks at all until
its lane runs on hosted CI, which is a round later at best.

`C1AY stock_config_tests` is that hole three times over. Its module is
`#[cfg(all(test, feature = "zenoh-config"))]` and its invocation applies a
substring filter, so it is out of scope on TWO of the lint's counts:

  * R2112 (`1c119ac2`) added a case and left the count at 32; hosted C1ay was
    red from that commit until R2117 found it while doing something else;
  * R2124 (`fda06748`) added another and left it at 33; R2129 paid it off;
  * R2166 (`4bf43166`) added `every_argv_only_key_says_which_kind_of_unproven_it_is`
    and left BOTH legs (37 and 42) where they were. Hosted run 33132637389 went
    red on the same push, and R2167 — this round — is the repayment.

Each round wrote the reason into a comment beside the guard, and the comment
R2117 wrote is quoted almost verbatim by the one R2124 wrote. A memo is not a
mechanism; this is the mechanism.

## Why this one must RUN, and why that is still cheap

The number is not derivable without resolving `#[cfg]` against a feature set,
which is a build. So this gate builds — but only when the push has plausibly
moved the test set a guard counts, and only the guards that push reaches:

  * the PACKAGE must be one the push changed;
  * the diff must add or remove a line that can change which tests EXIST — a
    `#[test]` / `#[ignore]` / `#[cfg]` / `#[cfg_attr]` attribute, or a `mod`
    declaration. A push that edits test BODIES cannot move a count and pays
    nothing. R2158 is why `#[cfg]` is in that list and `#[test]` alone is not:
    it moved two counts by REMOVING a feature gate above tests that already
    existed;
  * the guard's SELECTION must reach a changed file — `--test T` needs
    `tests/T.rs` itself to have changed, everything else needs a changed file
    under `src/`;
  * and when the guard applies a substring filter, that filter must occur in a
    changed file of that package.

MEASURED on R2166's own commit: 3 guards selected out of the 17 that name
`wz-ap-demo`, and out of 291 in the file. The whole C1ay lane is 175s; the two
legs this would have run are 27s and 17s.

## The one thing it deliberately does NOT do

It does not decide whether a guard is statically checkable. `count_guard_lint.py`
owns that judgement, and a second copy of it here would drift from the first the
day either moved — the very failure both gates are about, one level up. The
populations therefore OVERLAP rather than partition: a guard this selects may
also be checked statically, and running it twice costs time, never correctness.
Both read the same guard table through the same parser, imported from that file.

## The residue, stated rather than hidden

The filter test asks whether the filter STRING occurs in a file the push
changed. A test added to `src/a.rs` inside a module declared in `src/b.rs` is
therefore not selected when only `a.rs` changed. Widening it to the whole
package would select all 17 `wz-ap-demo` guards on any test edit, which is the
175s lane, so the narrow rule is a deliberate trade and not an oversight.
Hosted CI remains the full answer.

Usage:
    python3 scripts/lib/guarded_count_gate.py --range <base>..<head> [--verbose]
    python3 scripts/lib/guarded_count_gate.py --selftest
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import count_guard_lint as cgl  # noqa: E402  -- after the path insert

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNCI = REPO_ROOT / "scripts" / "run-ci.sh"
CRATES = REPO_ROOT / "crates"

# A line whose addition or removal can change which tests EXIST. Test BODIES are
# deliberately absent: editing one cannot move a count, and including them would
# make every crate push pay for a build.
TRIGGER_RE = re.compile(
    r"#\[(?:tokio::)?test\b"
    r"|#\[ignore\b"
    r"|#\[cfg\b"
    r"|#\[cfg_attr\b"
    r"|^\s*(?:pub\s+)?mod\s+[A-Za-z0-9_]+\s*[;{]"
)
SUMMARY_RE = re.compile(r"^test result: ok\. (\d+) passed", re.M)


class Guard:
    """One count guard, as `run-ci.sh` writes it."""

    def __init__(self, lineno, spelling, want, cmd, prelude=()):
        self.lineno = lineno
        self.spelling = spelling
        self.want = want
        self.cmd = cmd
        # Everything the line puts BEFORE `cargo` -- in practice an `env
        # VAR=... VAR=...` prefix. Carried rather than dropped because it is
        # part of what makes the command reproducible, and because dropping it
        # hid a shell expansion from the very check that exists to notice one:
        # R2200's Layer Z guard reads `env WZ_ZENOHD_BIN="$zenohd" ... cargo
        # test ...`, and with the prefix discarded the remaining tokens carry no
        # `$` at all.
        self.prelude = tuple(prelude)
        joined = " ".join(cmd)
        m = cgl.PKG_RE.search(joined)
        self.pkg = m.group(1) if m else None
        m = cgl.TEST_BIN_RE.search(joined)
        self.test_target = m.group(1) if m else None
        start = cmd.index("test") + 1 if "test" in cmd else len(cmd)
        _exact, self.filters, _skip = cgl.libtest_selection(cmd, start)

    @property
    def where(self):
        return f"run-ci.sh:{self.lineno}"

    def label(self):
        return f"{self.where} [{self.spelling}] {' '.join(self.cmd)}"

    @property
    def whole_command(self):
        """Every token the line spells for this guard, prefix included.

        What `SHELL_EXPANSION_RE` must be asked about: a command this runner
        cannot reproduce is unreproducible whichever half the shell assembles.
        """
        return self.prelude + tuple(self.cmd)


def parse_guards(text):
    """Every count guard with a NUMERIC expectation, in both spellings.

    A `+` expectation asserts that something ran, not how much; nothing here can
    contradict it, so it is not in the population. The parser itself is
    `count_guard_lint`'s — one guard table, read one way.
    """
    guards = []
    for lineno, logical in cgl.logical_lines(text):
        if logical.lstrip().startswith("#"):
            continue
        m = cgl.HELPER_RE.search(logical)
        if m:
            seg = logical[m.start():]
            g = _guard_from(lineno, "helper", int(m.group(1)), seg)
            if g:
                guards.append(g)
            continue
        for seg in logical.split("&&"):
            if not (cgl.CARGO_TEST_RE.search(seg) and cgl.GUARD_RE.search(seg)):
                continue
            want = int(cgl.GUARD_RE.search(seg).group(1))
            g = _guard_from(lineno, "bare", want, seg)
            if g:
                guards.append(g)
    attach_demo_builds(text, guards)
    return guards


# R2236 — the `wz-ap-demo` build a guard's own lane runs before it.
#
# Cargo uplifts every feature variant of one bin to ONE path (the R311y269
# note in run-ci), so `crates/target/debug/wz-ap-demo` is whatever the LAST
# build left there. A lane provisions its own demo and then runs its guards;
# this gate runs a guard's command ALONE, so it inherits whatever the previous
# pre-push step happened to build -- and a Layer Z guard against a
# default-feature demo does not print a wrong count, it prints
# `test result: FAILED` with six `wz_ap_demo_binary` preconditions panicking.
# The gate then reports UNMEASURED, and the hook fails a push on a gate that
# says, in its own words, that it measured nothing.
#
# MEASURED, R2236: with the Layer Z feature set the guarded command prints
# `test result: ok. 6 passed`; rebuilt at bare `cargo build -p wz-ap-demo` the
# same command prints `test result: FAILED. 0 passed; 6 failed`.
#
# So the build line is DERIVED rather than listed: scan BACKWARD from the
# guard for the nearest `cargo build -p wz-ap-demo ... --features <list>` that
# is still inside the same top-level lane function. A hand-kept table of
# "which guards need a demo" would be the escape hatch this file exists to
# avoid -- it would go stale the round a lane moves its build line, and
# nothing would measure that.
# R2248 — the feature list is OPTIONAL, and requiring it was a hole rather than
# a narrowing. The clause this regex serves is "a lane that builds the demo is a
# lane whose guards depend on machine-local provisioning", and a FEATURELESS
# `cargo build -p wz-ap-demo --quiet` is such a build: Layer Ewire runs exactly
# that, and its guards need `target/zenoh-pico-cli/z_put` besides. With the
# features mandatory those guards read as demo-free, were routed to a build
# host, and came back with no libtest summary at all -- `UNMEASURED`, which is
# this gate refusing to invent a number and is why the hole surfaced instead of
# passing. A guard's routing must follow the DEMO, not the feature list.
DEMO_BUILD_RE = re.compile(
    r"cargo build -p wz-ap-demo\b(?:[^\n|)]*?--features ([A-Za-z0-9_,-]+))?"
)
FN_OPEN_RE = re.compile(r"^[a-z_][a-z0-9_]*\(\) \{")


def attach_demo_builds(text, guards):
    """Give each guard the feature list its own lane builds the demo with.

    `None` when the enclosing lane builds no demo -- that guard's command does
    not depend on one, and running a build for it would be a cost with no
    claim behind it.
    """
    lines = text.splitlines()
    for g in guards:
        features = None
        for i in range(min(g.lineno, len(lines)) - 1, -1, -1):
            line = lines[i]
            if FN_OPEN_RE.match(line):
                break  # left the lane; a build in another one is not this guard's
            if line.lstrip().startswith("#"):
                continue
            m = DEMO_BUILD_RE.search(line)
            if m:
                # `""` (a featureless build) and `None` (no build in this lane)
                # are DIFFERENT answers and the caller branches on which. A
                # falsy-test would fold them and put the featureless case back
                # on the build host.
                features = m.group(1) or ""
                break
        g.demo_features = features
    return guards


def _guard_from(lineno, spelling, want, seg):
    toks = cgl.command_tokens(seg)
    if "cargo" not in toks:
        return None
    at = toks.index("cargo")
    cmd = toks[at:]
    if len(cmd) < 2 or cmd[1] != "test":
        return None
    # The tokens before `cargo` are the guard's label and any `env` prefix. Only
    # the run of tokens from `env` onwards is part of the COMMAND; the label is
    # the helper's own argument and its quoting says nothing about whether the
    # command can be reproduced.
    prelude = toks[toks.index("env", 0, at):at] if "env" in toks[:at] else ()
    return Guard(lineno, spelling, want, cmd, prelude)


def dir_for_package(pkg, manifest_names):
    for d, name in manifest_names.items():
        if name == pkg:
            return d
    return None


def package_manifest_names(crates_root=None):
    root = crates_root or CRATES
    names = {}
    if not root.is_dir():
        return names
    for manifest in sorted(root.glob("*/Cargo.toml")):
        for line in manifest.read_text().split("\n"):
            m = re.match(r'^name\s*=\s*"([^"]+)"', line)
            if m:
                names[manifest.parent.name] = m.group(1)
                break
    return names


def select(guards, changed_files, changed_lines, manifest_names, read_text):
    """`(selected, skipped)` — which guards this push must RUN, and why not.

    `changed_files`  repo-relative paths the push touched.
    `changed_lines`  {crate dir: [added/removed line bodies]} from `-U0`.
    `read_text`      crate-dir-relative path -> current text (injectable so the
                     selftest never needs a tree on disk).
    """
    by_dir = {}
    for f in changed_files:
        m = re.match(r"crates/([^/]+)/(.*)$", f)
        if m:
            by_dir.setdefault(m.group(1), []).append(m.group(2))

    triggered = {
        d for d, lines in changed_lines.items() if any(TRIGGER_RE.search(l) for l in lines)
    }

    selected, skipped = [], []
    for g in guards:
        if g.pkg is None:
            skipped.append((g, "names no package"))
            continue
        if any(cgl.SHELL_EXPANSION_RE.search(t) for t in g.whole_command):
            skipped.append((g, "the shell assembles part of this command"))
            continue
        d = dir_for_package(g.pkg, manifest_names)
        if d is None or d not in by_dir:
            continue
        if d not in triggered:
            continue
        rels = by_dir[d]
        if g.test_target is not None:
            if f"tests/{g.test_target}.rs" not in rels:
                continue
            reachable = [f"tests/{g.test_target}.rs"]
        else:
            reachable = [r for r in rels if r.startswith("src/") and r.endswith(".rs")]
            if not reachable:
                continue
        if g.filters:
            haystack = "\n".join(read_text(d, r) for r in reachable)
            haystack += "\n" + "\n".join(changed_lines.get(d, []))
            if not any(f in haystack for f in g.filters):
                continue
        selected.append(g)
    return selected, skipped


def verdict(want, rc, output):
    """`(status, counts_seen)` — and THREE statuses, not two.

    `_runci_guarded_test` greps the whole captured output, so ANY summary line
    matching satisfies it. Reading only the last one would make this gate and
    the lane disagree about the same run, which is worse than either verdict.

    The third status is the one this file was WRONG about until it was probed.
    The first draft folded "no libtest summary at all" into "the count moved",
    and every guard then reported `declares 37 passed, the run printed no
    summary line` — a sentence that reads as a measurement of a number when in
    fact NOTHING was measured. That is R2164's class exactly: a gate covering
    two kinds of failure with one verdict pronounces on a subject it never
    reached. `UNMEASURED` is a broken instrument and says so; `MOVED` is the
    count claim and is the only one that means edit the constant.
    """
    counts = [int(m.group(1)) for m in SUMMARY_RE.finditer(output)]
    if not counts:
        return "UNMEASURED", counts
    if rc != 0:
        return "FAILED", counts
    return ("OK" if want in counts else "MOVED"), counts


def run_guard(g, verbose):
    """Run one guard and read its libtest summary out of the run's OWN output.

    ⚠ `$BX` NEEDS THE LOG, NOT THE PIPE. The wrapper prints a banner and puts
    the wrapped command's output in a file, so capturing its stdout yields a
    run with no summary line in it — which is how the probe above found the
    `UNMEASURED` hole. The banner names the file; this reads it. When it names
    none, that is an INPUT error and the caller is told so, rather than a
    number being invented for it.
    """
    cmd = list(g.cmd)
    bx = os.environ.get("BX", "")
    routed = bool(bx) and os.access(bx, os.X_OK)
    # R2236 — provision the demo the guard's own lane provisions, FIRST. See
    # `attach_demo_builds`: without this the command runs against whatever the
    # previous pre-push step left at the one uplifted bin path, and a Layer Z
    # guard then fails its preconditions instead of reporting a count.
    features = getattr(g, "demo_features", None)
    if features is not None:
        # ...and run it HERE, never through `$BX`. A lane that builds a demo is
        # a lane whose guards depend on machine-local provisioning -- the demo
        # at the one uplifted bin path, plus `target/zenohd/zenohd` and
        # `target/zenoh-pico-cli/*`, none of which a remote builder has.
        # MEASURED, R2236: routed to a build host the same command reported
        # `z_sub binary missing at /home/<other-host>/.../target/zenoh-pico-cli/z_sub`
        # and `--peer requires the routing-peer feature`, i.e. it was answering
        # about a machine that was never provisioned. "Has a demo build" is the
        # DERIVED test for that dependence; a hand-kept list of oracle-needing
        # guards would go stale the round a lane moves.
        routed = False
        build = ["cargo", "build", "-p", "wz-ap-demo", "--quiet"]
        if features:
            build[4:4] = ["--features", features]
        if verbose:
            print(f"  provisioning {' '.join(build)}")
        pre = subprocess.run(
            build, cwd=str(REPO_ROOT / "crates"), capture_output=True, text=True
        )
        if pre.returncode != 0:
            # Say WHICH half failed. A build error here is not a count claim,
            # and folding it into the run's verdict would blame the guard.
            if verbose:
                print(f"  demo build failed for {g.where}:\n{pre.stdout}{pre.stderr}")
            return "UNMEASURED", []
    if routed:
        cmd = [bx, "--label", f"guard-count-{g.lineno}", "--"] + cmd
    if verbose:
        print(f"  running {' '.join(cmd)}")
    proc = subprocess.run(
        cmd, cwd=str(REPO_ROOT / "crates"), capture_output=True, text=True
    )
    output = proc.stdout + proc.stderr
    if routed:
        m = re.search(r"full log: (\S+)", output)
        if not m:
            return "UNMEASURED", []
        try:
            output += "\n" + Path(m.group(1)).read_text()
        except OSError:
            return "UNMEASURED", []
    return verdict(g.want, proc.returncode, output)


def changed_from_git(rng):
    files = subprocess.run(
        ["git", "diff", "--name-only", rng, "--", "crates/"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, check=True,
    ).stdout.split("\n")
    files = [f for f in files if f]
    raw = subprocess.run(
        ["git", "diff", "-U0", rng, "--", "crates/"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, check=True,
    ).stdout
    lines = {}
    cur = None
    for ln in raw.split("\n"):
        m = re.match(r"^\+\+\+ b/crates/([^/]+)/", ln)
        if m:
            cur = m.group(1)
            continue
        if ln.startswith("--- ") or ln.startswith("+++ "):
            continue
        if cur and (ln.startswith("+") or ln.startswith("-")):
            lines.setdefault(cur, []).append(ln[1:])
    return files, lines


def _read_worktree(d, rel):
    p = CRATES / d / rel
    try:
        return p.read_text()
    except OSError:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--range", dest="rng")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    # Which `run-ci.sh` to read the declared numbers from. The worktree's is the
    # only answer a HOOK ever wants — the push is what it is gating. This exists
    # so the gate can be aimed at a PAST state and shown to fail there, which is
    # how R2167 established that it would have caught R2166 rather than
    # asserting it. A gate whose enforcement was never measured is a claim.
    ap.add_argument("--run-ci", dest="runci", default=None)
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.rng:
        print("usage: guarded_count_gate.py --range <base>..<head>", file=sys.stderr)
        return 2

    runci = Path(args.runci) if args.runci else RUNCI
    guards = parse_guards(runci.read_text())
    if not guards:
        print(
            "guarded-count gate FAIL: parsed ZERO count guards out of "
            f"{RUNCI.relative_to(REPO_ROOT)}. Either the guard population "
            "changed shape or the parser did — both make a green run "
            "meaningless.",
            file=sys.stderr,
        )
        return 1

    files, lines = changed_from_git(args.rng)
    manifest_names = package_manifest_names()
    selected, skipped = select(guards, files, lines, manifest_names, _read_worktree)

    print(
        f"guarded-count gate: {len(guards)} numeric count guard(s) in "
        f"run-ci.sh; {len(selected)} reached by this push"
    )
    if args.verbose and skipped:
        for g, why in skipped:
            print(f"  unrunnable {g.where}: {why}")
    if not selected:
        print("  no guard's test set is moved by this push; nothing to run.")
        return 0

    moved, broken = [], []
    for g in selected:
        status, counts = run_guard(g, args.verbose)
        seen = ", ".join(str(c) for c in counts)
        if status == "OK":
            print(f"  OK  {g.where}: {g.want} passed")
        elif status == "MOVED":
            moved.append(
                f"{g.where}: declares {g.want} passed, the run printed {seen}\n"
                f"      {' '.join(g.cmd)}"
            )
        elif status == "FAILED":
            broken.append(
                f"{g.where}: the command exited non-zero (it printed {seen})\n"
                f"      {' '.join(g.cmd)}"
            )
        else:
            broken.append(
                f"{g.where}: NO libtest summary in the run's output — this gate "
                f"measured nothing, so it is not saying the count is wrong\n"
                f"      {' '.join(g.cmd)}"
            )

    if broken:
        print("", file=sys.stderr)
        print("guarded-count gate INPUT ERROR:", file=sys.stderr)
        for f in broken:
            print(f"  - {f}", file=sys.stderr)
        print(
            "\n  Fix the run before reading anything into the numbers above.",
            file=sys.stderr,
        )
        return 2
    if moved:
        print("", file=sys.stderr)
        print("guarded-count gate FAIL:", file=sys.stderr)
        for f in moved:
            print(f"  - {f}", file=sys.stderr)
        print("", file=sys.stderr)
        print(
            "  This push moves a test set a run-ci count guard counts, and the "
            "guard\n  still declares the old number. Move the constant IN THIS "
            "COMMIT, and move\n  it to what the command above PRINTED — never "
            "to what the diff suggests: the\n  module's other cases are "
            "`#[cfg]`-gated, so counting the diff has produced\n  the wrong "
            "number before (run-ci.sh's own comment records it).",
            file=sys.stderr,
        )
        return 1
    return 0


# ── selftest ────────────────────────────────────────────────────────────
# Each arm is a case an obvious implementation gets WRONG. An arm that would be
# green against a naive version measures nothing, which is the trap R2137 found
# in six of its own fixtures — so the reason each one discriminates is named.

FIXTURE = """
    _runci_guarded_test "C1AY stock_config_tests 37" 37 \\
        cargo test -p demo-crate --features zenoh-config stock_config_tests --quiet || return 1
    _runci_guarded_test "C1AY topology 4" 4 \\
        cargo test -p demo-crate --features zenoh-config --test topology_binary --quiet || return 1
    _runci_guarded_test "C1AY other 9" 9 \\
        cargo test -p other-crate --features x other_tests --quiet || return 1
    _runci_guarded_test "C1AY loop $leg 2" 2 \\
        cargo test -p demo-crate --exact "$leg" --quiet || return 1
    _runci_guarded_test "Z oracle 3" 3 env DEMO_ORACLE_BIN="$oracle" \\
        cargo test -p demo-crate --test topology_binary --quiet || return 1
    _runci_guarded_test "Z fixed 5" 5 env DEMO_ORACLE_BIN=/opt/fixed \\
        cargo test -p demo-crate --test topology_binary --quiet || return 1
"""

MANIFESTS = {"demo": "demo-crate", "other": "other-crate", "third": "other-crate"}
SRC = {
    ("demo", "src/args.rs"): "mod stock_config_tests {\n fn a() {}\n}\n",
    ("demo", "tests/topology_binary.rs"): "#[test]\nfn t() {}\n",
}


def _reader(d, rel):
    return SRC.get((d, rel), "")


def selftest():
    guards = parse_guards(FIXTURE)
    arms = []

    def arm(name, cond, why):
        arms.append((name, bool(cond), why))

    arm(
        "parse: every numeric guard, the unrunnable ones carried too",
        len(guards) == 6 and [g.want for g in guards] == [37, 4, 9, 2, 3, 5],
        "a parser that cut at the label would find the wrong command",
    )

    # The R2166 case itself: the added test's NAME appears nowhere in the
    # guard's filter — only the enclosing MODULE does. An implementation that
    # matched the filter against added function names misses it entirely.
    sel, skip = select(
        guards,
        ["crates/demo/src/args.rs"],
        {"demo": ["    #[test]", "    fn every_argv_only_key_says_which_kind() {}"]},
        MANIFESTS,
        _reader,
    )
    arm(
        "R2166: filter matches the MODULE, not the added fn",
        [g.want for g in sel] == [37],
        "matching the filter against the added fn name finds nothing",
    )
    arm(
        "the $leg guard is reported unrunnable, not silently dropped",
        any("shell assembles" in w for _g, w in skip),
        "a silent drop reads exactly like coverage",
    )

    # R2200: the expansion is in the `env` PREFIX, which the parser used to
    # discard before this check ever saw it. The remaining tokens carry no `$`,
    # so the old reader selected the guard, ran it somewhere the shell-supplied
    # oracle does not exist, and reported UNMEASURED -- a broken instrument
    # blocking a push over a count it never read. The control below is the half
    # that keeps this from being a blanket excuse for an `env` prefix.
    sel_env, skip_env = select(
        guards,
        ["crates/demo/tests/topology_binary.rs"],
        {"demo": ["#[test]"]},
        MANIFESTS,
        _reader,
    )
    arm(
        "R2200: a shell-assembled env PREFIX makes the guard unrunnable",
        3 not in [g.want for g in sel_env]
        and any(g.want == 3 and "shell assembles" in w for g, w in skip_env),
        "the prefix is part of the command; dropping it hides the expansion",
    )
    arm(
        "CONTROL: a LITERAL env prefix stays runnable",
        5 in [g.want for g in sel_env],
        "skipping every `env` prefix would excuse the reproducible ones too",
    )

    # A package the push did not touch must not be selected. An implementation
    # that ran every guard for a changed FILE SET would pull `other-crate` in.
    sel, _ = select(
        guards, ["crates/demo/src/args.rs"], {"demo": ["#[test]"]}, MANIFESTS, _reader
    )
    arm(
        "an untouched package is not selected",
        all(g.pkg == "demo-crate" for g in sel),
        "running every guard makes the gate the 175s lane",
    )

    # `--test T` reaches only its OWN file. Selecting it because the crate
    # changed would build a target the push cannot have moved.
    sel, _ = select(
        guards, ["crates/demo/src/args.rs"], {"demo": ["#[test]"]}, MANIFESTS, _reader
    )
    arm(
        "a --test guard is NOT reached by a src/ change",
        all(g.test_target is None for g in sel),
        "'the crate changed' would select it and build for nothing",
    )
    sel, _ = select(
        guards,
        ["crates/demo/tests/topology_binary.rs"],
        {"demo": ["#[test]"]},
        MANIFESTS,
        _reader,
    )
    arm(
        # NON-EMPTY first, `all` second. `all` over an empty list is true, so
        # the second half alone would report green on exactly the failure this
        # arm exists to catch. The count is deliberately NOT pinned: how many
        # guards the fixture aims at this target is a property of the fixture,
        # and pinning it made this arm red when R2200 widened the fixture for a
        # different rule.
        "a --test guard IS reached by its own file",
        sel and all(g.test_target == "topology_binary" for g in sel),
        "the previous arm alone would also pass if nothing were ever selected",
    )

    # A body-only edit cannot move a count. Without the trigger this builds on
    # every crate push.
    sel, _ = select(
        guards,
        ["crates/demo/src/args.rs"],
        {"demo": ["    assert_eq!(a, b);"]},
        MANIFESTS,
        _reader,
    )
    arm(
        "a body-only edit triggers nothing",
        sel == [],
        "no trigger means every crate push pays for a build",
    )

    # R2158's shape: a feature gate REMOVED above tests that already existed.
    # `#[test]`-only triggering misses it, and that push moved two counts.
    sel, _ = select(
        guards,
        ["crates/demo/src/args.rs"],
        {"demo": ['    #[cfg(feature = "routing-peer")]']},
        MANIFESTS,
        _reader,
    )
    arm(
        "R2158: a removed #[cfg] triggers",
        [g.want for g in sel] == [37],
        "triggering on #[test] alone misses the gate-removal shape",
    )

    # The lane greps the WHOLE output. A verdict reading only the last summary
    # disagrees with the lane about the same run.
    arm(
        "verdict: any summary line satisfies, as the lane does",
        verdict(38, 0, "test result: ok. 38 passed\ntest result: ok. 0 passed")
        == ("OK", [38, 0]),
        "reading the last summary contradicts _runci_guarded_test",
    )
    arm(
        "verdict: a moved count is MOVED and reports what it saw",
        verdict(37, 0, "test result: ok. 38 passed") == ("MOVED", [38]),
        "the number seen is what the author must copy",
    )
    arm(
        "verdict: a non-zero exit is not a count claim",
        verdict(38, 101, "test result: ok. 38 passed") == ("FAILED", [38]),
        "a crashed run can still have printed a passing summary",
    )
    # The hole the R2166 probe found in THIS file: routed through `$BX` the
    # summary is in a log the wrapper names, so the captured stdout has none,
    # and the first draft called that `declares 37, printed no summary line` —
    # a sentence about a number, from a run that measured none.
    arm(
        "verdict: no summary at all is UNMEASURED, not a moved count",
        verdict(37, 0, "bx: exit=0 in 27s — full log: /x.log")
        == ("UNMEASURED", []),
        "folding it into MOVED pronounces on a subject never reached",
    )

    # R2236 — the demo a guard's lane provisions, DERIVED. The fixture carries
    # the shape the previous implementation swallowed: a guard whose lane builds
    # the demo (so the guard depends on machine-local provisioning) and a guard
    # in a LATER function that must NOT inherit that build. Without the second
    # arm the derivation could be "the nearest build anywhere above", which is
    # green on the first arm alone and wrong for every lane after a demo lane.
    demo_fixture = "\n".join(
        [
            "layer_with_a_demo() {",
            "    (cd crates && cargo build -p wz-ap-demo --features quic,routing-peer"
            " --quiet) || return 1",
            "    _runci_guarded_test A 6 cargo test -p p --test t -- --ignored",
            "}",
            "layer_without_one() {",
            "    _runci_guarded_test B 3 cargo test -p p --test u -- --ignored",
            "}",
            # R2248 — the shape the OLD regex swallowed: Layer Ewire's build
            # names no features, and requiring them read this lane as demo-free.
            "layer_with_a_featureless_demo() {",
            "    (cd crates && cargo build -p wz-ap-demo --quiet) || return 1",
            "    _runci_guarded_test C 1 cargo test -p p --test v -- --ignored",
            "}",
        ]
    )
    dg = parse_guards(demo_fixture)
    arm(
        "R2236: a guard inherits its OWN lane's demo build",
        len(dg) == 3 and dg[0].demo_features == "quic,routing-peer",
        "a guard run without its lane's demo answers about the wrong binary",
    )
    arm(
        "R2236: the scan stops at the function boundary (the control)",
        len(dg) == 3 and dg[1].demo_features is None,
        "inheriting a previous lane's build would provision the wrong features",
    )
    arm(
        "R2248: a FEATURELESS demo build is still a demo build",
        len(dg) == 3 and dg[2].demo_features == "",
        "requiring --features read Layer Ewire as demo-free, routed its guard "
        "to a build host that has no zenoh-pico CLI, and the run came back "
        "with no libtest summary at all",
    )
    arm(
        "R2248: and `` is not `None` -- the two answers stay apart (the control)",
        len(dg) == 3 and dg[2].demo_features is not None and dg[1].demo_features is None,
        "folding the featureless case into None puts it back on the build host",
    )

    bad = [(n, w) for n, ok, w in arms if not ok]
    print(f"guarded-count gate selftest: {len(arms) - len(bad)}/{len(arms)} arm(s) OK")
    for name, ok, _ in arms:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if bad:
        print("", file=sys.stderr)
        for name, why in bad:
            print(f"selftest FAIL: {name} — {why}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
