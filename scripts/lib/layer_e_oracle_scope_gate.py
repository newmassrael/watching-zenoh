#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2358 (no register item) -- Layer E must not SELECT a test whose oracle it
does not PROVISION.

THE DEFECT, and why it went six hosted runs without being caught.

Layer E sweeps `cargo test -p wz-integration-tests -- --ignored` minus a
hand-written list of name tokens. The sweep therefore ADOPTS every ignored test
added to that crate, automatically and silently. The job itself builds two
things: the zenoh-pico CLI binaries and `wz-ap-demo`. It does NOT build zenohd
or the core zenoh examples -- that is the zenohd-provisioning lane's job.

R2350 added three tests that drive the zenoh CORE EXAMPLE `z_get`. Their names
match no token, so the sweep took them, and the helper that resolves that binary
asserts rather than skipping -- deliberately, because "a missing oracle must not
degrade into a green run". So the lane panicked on a binary it was never going
to have, and it did so on every push until this gate existed.

The lane's own comment already recorded the shape: the token list "has been
extended twice already", then a third time, and -- in its own words -- "the
sweep is not count-guarded, so there is no number to follow it". Three
extensions and a stated blind spot is a class, not an accident. A memo is not a
mechanism.

THE POPULATION IS DERIVED FROM BOTH SIDES, which is the whole design.

  SELECTED   = the ignored test fns in that crate MINUS the tokens actually
               written in `run-ci.sh`. The token list is PARSED OUT of the sweep
               line, never copied here -- a second copy would drift the day
               either moves, and drift is this gate's own subject.
  NEEDS_ORACLE = a test whose FILE reaches a binary family this job does not
               build. Derived from the helper NAME the test calls, not from a
               list of test names.
  OFFENDER   = the intersection. It must be empty.

⚠ THE FIRST DRAFT OF THIS SCAN REPORTED ZERO OFFENDERS while three tests were
red on hosted CI, and the reason is worth keeping: it looked for the literal
`#[tokio::test]`, and this tree writes
`#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`. The bracketed
form never matched, so the scan read an imagined tree and agreed with nothing.
The selftest fixtures below therefore use the PARAMETERISED attribute, because a
fixture tidier than the tree measures the fixture.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TEST_DIR = pathlib.Path("crates/wz-integration-tests/tests")
RUN_CI = pathlib.Path("scripts/run-ci.sh")

#: Helpers that resolve a binary Layer E does NOT build. Each names a FAMILY,
#: not a file: the zenohd-provisioning lane builds these from the pinned
#: checkout, and this job builds only the pico CLI and wz-ap-demo.
UNPROVISIONED_HELPERS = ("zenoh_core_example_binary", "zenoh_ext_example_binary")

#: The sweep line is found by the crate it runs, so a rename of the lane
#: function cannot hide it.
#:
#: ⚠ CANDIDATES ARE FILTERED, NOT TAKEN FIRST. `run-ci.sh` mentions this exact
#: command as a STRING LITERAL in the lane's own selfcheck, and the first draft
#: of this gate matched that mention and reported "0 skip token(s)" -- which
#: would have made every selected test an offender for a reason that had nothing
#: to do with the tree. The real invocation is the one that carries `--skip`
#: tokens; exactly one must, and both zero and several are a FAIL rather than a
#: guess.
SWEEP = re.compile(
    r"cargo test -p wz-integration-tests[^\n]*--ignored((?:[^\n)]|\n\s*)*)", re.M
)
TOKEN = re.compile(r"--skip\s+(\S+)")
FN = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*\(", re.M)

#: Below this the scan stopped matching the tree rather than the tree becoming
#: clean. Layer E selects over a hundred ignored tests.
MIN_SELECTED = 60


def sweep_tokens(root: pathlib.Path) -> list[str]:
    text = (root / RUN_CI).read_text(errors="replace")
    with_tokens = [m for m in SWEEP.finditer(text) if TOKEN.findall(m.group(0))]
    if len(with_tokens) != 1:
        raise SystemExit(
            "FAIL: expected exactly ONE `cargo test -p wz-integration-tests -- "
            "--ignored` invocation carrying `--skip` tokens in %s, found %d. Zero "
            "means the lane was renamed or restructured and this gate grades a "
            "sweep that no longer exists -- repoint it, do not delete it. Several "
            "means the scope is split and picking one would be a guess."
            % (RUN_CI, len(with_tokens))
        )
    return TOKEN.findall(with_tokens[0].group(0))


def scan(root: pathlib.Path):
    """`(selected, offenders)` -- both derived, neither listed."""
    tokens = sweep_tokens(root)
    selected: list[tuple[str, str]] = []
    offenders: list[tuple[str, str, str]] = []
    for path in sorted((root / TEST_DIR).glob("*.rs")):
        text = path.read_text(errors="replace")
        needs = [h for h in UNPROVISIONED_HELPERS if h in text]
        for m in FN.finditer(text):
            name = m.group(1)
            head = text[max(0, m.start() - 400):m.start()]
            # NOT the bracketed literal -- see the module docstring.
            if "#[test]" not in head and "tokio::test" not in head:
                continue
            if "ignore" not in head:
                continue
            if any(tok in name for tok in tokens):
                continue
            selected.append((name, path.name))
            if needs:
                offenders.append((name, path.name, needs[0]))
    return selected, offenders, tokens


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    root = pathlib.Path(args.root)
    selected, offenders, tokens = scan(root)
    print(
        "layer-e-oracle-scope: %d ignored test(s) selected after %d skip token(s); "
        "%d need a binary this lane does not build"
        % (len(selected), len(tokens), len(offenders))
    )
    if len(selected) < MIN_SELECTED:
        print(
            "FAIL: only %d selected test(s), expected at least %d. A population "
            "that collapsed means this scan stopped matching the tree, not that "
            "the lane stopped sweeping." % (len(selected), MIN_SELECTED)
        )
        return 1
    if offenders:
        print("FAIL: Layer E SELECTS %d test(s) whose oracle it does not "
              "PROVISION:" % len(offenders))
        for name, f, helper in offenders:
            print("    - %s  (%s, calls %s)" % (name, f, helper))
        print(
            "      This job builds the zenoh-pico CLI and wz-ap-demo. A test that\n"
            "      reaches a zenohd-family binary belongs to the lane that builds\n"
            "      one. Add a `--skip` token to the sweep that covers it, and\n"
            "      CHECK THE TOKEN BOTH WAYS -- it must remove every offender and\n"
            "      no other selected test."
        )
        return 1
    print("layer-e-oracle-scope OK")
    return 0


def selftest() -> int:
    """Fixtures in the shapes this tree writes, not tidier ones."""
    import shutil
    import tempfile

    SWEEP_LINE = (
        "layer_e() {\n"
        "    (cd crates && cargo test -p wz-integration-tests --quiet -- --ignored \\\n"
        "        --skip wz_e2e_ --skip zenoh_zget)\n}\n"
    )
    # The PARAMETERISED attribute, deliberately: the bracketed literal is what
    # the first draft looked for and it never matches this tree.
    TOK = '#[tokio::test(flavor = "multi_thread", worker_threads = 2)]\n'
    IGN = '#[ignore = "binary-dep e2e"]\n'
    CALL = "let p = zenoh_core_example_binary(\"z_get\");\n"

    cases = [
        ("a selected test needing an unprovisioned oracle is an OFFENDER",
         TOK + IGN + "async fn wz_history_replies(x: u8) {\n" + CALL + "}\n", 1),
        ("the same test, covered by a skip token, is not",
         TOK + IGN + "async fn a_zenoh_zget_case(x: u8) {\n" + CALL + "}\n", 0),
        ("a selected test that needs NO such oracle is not",
         TOK + IGN + "async fn wz_plain_case(x: u8) {\n let y = 1;\n}\n", 0),
        ("a NON-ignored test is outside the sweep entirely",
         TOK + "async fn wz_not_ignored(x: u8) {\n" + CALL + "}\n", 0),
        ("the parameterised tokio attribute is recognised (the first draft's bug)",
         TOK + IGN + "async fn wz_param_attr(x: u8) {\n" + CALL + "}\n", 1),
    ]
    failures = 0
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="wz-layere-selftest-"))
    try:
        (tmp / RUN_CI.parent).mkdir(parents=True, exist_ok=True)
        (tmp / RUN_CI).write_text(SWEEP_LINE, encoding="utf-8")
        (tmp / TEST_DIR).mkdir(parents=True, exist_ok=True)
        for name, body, want in cases:
            for stale in (tmp / TEST_DIR).glob("*.rs"):
                stale.unlink()
            (tmp / TEST_DIR / "case.rs").write_text(body, encoding="utf-8")
            _, offenders, _ = scan(tmp)
            if len(offenders) != want:
                print("  selftest FAIL  %s: offenders=%d want %d"
                      % (name, len(offenders), want))
                failures += 1
            else:
                print("  selftest ok    %s" % name)

        # The token list must be READ, not assumed: emptying it turns the
        # covered case back into an offender.
        (tmp / RUN_CI).write_text(
            SWEEP_LINE.replace(" --skip zenoh_zget", ""), encoding="utf-8")
        (tmp / TEST_DIR / "case.rs").write_text(
            TOK + IGN + "async fn a_zenoh_zget_case(x: u8) {\n" + CALL + "}\n",
            encoding="utf-8")
        _, offenders, _ = scan(tmp)
        if len(offenders) != 1:
            print("  selftest FAIL  removing the token must re-offend the case")
            failures += 1
        else:
            print("  selftest ok    the skip list is READ from run-ci.sh, not assumed")

        # A sweep this gate cannot find must FAIL, never pass silently.
        (tmp / RUN_CI).write_text("layer_e() { echo nothing; }\n", encoding="utf-8")
        try:
            scan(tmp)
            print("  selftest FAIL  a missing sweep must not be a silent pass")
            failures += 1
        except SystemExit:
            print("  selftest ok    a sweep this gate cannot find FAILs")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("layer-e-oracle-scope selftest: %d failure(s)" % failures)
        return 1
    print("layer-e-oracle-scope selftest OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
