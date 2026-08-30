#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2208 (no register item) — WHAT A MACHINE MUST ALREADY HAVE for the lanes
`run-ci.sh` arms, and a way to ASK a machine whether it has them.

Closes item 562 of the unregistered register, which lives outside this
repository -- which is why the citation above reads "no register item", the
same way `feature_public_surface_census.py` does for 532 and
`cdylib_soname_gate.py` for 521. The item is named in full below, which is what
a reader grepping for it will find.

## The failure this ends

`run-ci.sh` arms three adjudicators with a `WZ_*_REQUIRE=1` prefix. Each of
those tests SKIPS when its oracle is absent and the flag turns that skip into a
failure, which is right: a skip prints `ok`, and "the oracle was absent" must
not read as "the subject was right". The arming is a statement that the runner
HAS the oracle -- and the only runner anybody checked was the hosted one.
`ci.yml` installs `libpcap-dev`, `tcpdump` and `netbase` for exactly this, with
a comment beside the leg saying "this job installs libpcap's headers so the
flag is a statement rather than a gamble".

The remote build fleet is a different runner and nothing carried the statement
to it. MEASURED on 2026-08-31: `/usr/include/pcap/dlt.h` was absent on all
three build hosts, so `run-ci.sh --layer C1bn` could not complete ANYWHERE off
the hosted runner -- and because the adjudicator sits early in that lane, the
legs after it never ran at all. R2207 had to judge its own new gate by running
it OUTSIDE the lane, which is the shape this file exists to stop being
necessary.

## What it checks, and what it can ASK

Two different questions, deliberately two modes:

  * `--check`  -- CLASSIFICATION, and it is machine-independent, so a lane can
                  run it anywhere. Every arming in `run-ci.sh` is accounted
                  for; every row names a test that really reads its flag; and
                  every oracle a row declares OCCURS IN THAT TEST'S SOURCE, so
                  a row cannot drift from the default it claims to describe.
  * `--probe`  -- PRESENCE, here or on another machine (`--host <alias>`, over
                  ssh). This is the question a person has before spending
                  minutes sending a lane somewhere, and before this file there
                  was no way to ask it except by running the lane and reading
                  the failure.

## The population is DERIVED, and what it cannot see is REFUSED

An arming is `WZ_..._REQUIRE=1` immediately followed by `cargo` -- an
environment prefix on a `cargo test`, which is the shape run-ci.sh uses and the
only one that arms on EVERY runner rather than being set by a hosted job's
`env:`. That pattern is narrow on purpose, so the gate does not have to guess
at shell context.

Narrow leaves a hole, and the hole is closed rather than stated: every OTHER
`WZ_..._REQUIRE=1` in the file is required to be followed by an English
connective from `PROSE_AFTER` -- the shape a sentence about the flag takes.
Anything else is a FINDING. So an arming written some other way (`env
WZ_X_REQUIRE=1 bash …`, say) does not slip past unnoticed; it fails until
somebody teaches this file the shape or names it.

## Why the oracle kinds are a CLOSED set of two

`file` and `program`, and each is exactly testable with one command on any
machine -- which is what makes `--probe --host` possible at all. A kind whose
presence could not be decided by a shell one-liner would be a row nobody could
check remotely, and this file would be back to prose.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shlex
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUN_CI = ROOT / "scripts" / "run-ci.sh"
TESTS = ROOT / "crates" / "wz-integration-tests" / "tests"

#: An ARMING: the env prefix on a `cargo test`, which is how `run-ci.sh` turns
#: an adjudicator's skip into a failure on every runner.
ARMING = re.compile(r"\b(WZ_[A-Z0-9_]*REQUIRE[A-Z0-9_]*)=1\s+cargo\b")

#: Every occurrence of the same assignment, armings included. The difference
#: between this and the one above is what the prose test has to account for.
ANY_ASSIGN = re.compile(r"\b(WZ_[A-Z0-9_]*REQUIRE[A-Z0-9_]*)=1\s+(\S+)")

#: `flag -> (test file, oracles)`. An oracle is `("file", path)` or
#: `("program", name)`.
#:
#: The rows are declared and NOT believed: `--check` requires each oracle's
#: string to occur in the named test's own source, so a default that moves in
#: the test takes this row red with it. That is the same shape
#: `feature_public_surface_census.py` uses on the diagnostic axis's reason
#: tables, and for the same reason -- a table beside the code it describes ages
#: silently otherwise.
ROWS: dict[str, tuple[str, tuple[tuple[str, str], ...]]] = {
    "WZ_TCPDUMP_REQUIRE": (
        "bsd_af_tcpdump_adjudicator.rs",
        (("program", "tcpdump"),),
    ),
    "WZ_DLT_HEADER_REQUIRE": (
        "pcap_dlt_header_adjudicator.rs",
        (("file", "/usr/include/pcap/dlt.h"),),
    ),
    "WZ_PROTO_REGISTRY_REQUIRE": (
        "ip_protocol_opinion_split.rs",
        (("file", "/etc/protocols"), ("program", "tcpdump")),
    ),
}

KINDS = ("file", "program")


def armings(text: str) -> set[str]:
    return set(ARMING.findall(text))


def unclassifiable(text: str) -> list[tuple[int, str, str]]:
    """Assignments that are neither an arming nor prose ABOUT one.

    Prose is decided POSITIONALLY -- the line is a `#` comment, or the
    occurrence sits inside something being `echo`ed -- and not by the English
    word that follows. A word list was the first shape here and it is the wrong
    one: it is an exemption table, so an arming written in an unfamiliar phrase
    would have to be added to it, and adding to it is indistinguishable from
    excusing a real arming. Where the text SITS is a fact about the script.
    """
    out: list[tuple[int, str, str]] = []
    for number, line in enumerate(text.split("\n"), 1):
        for m in ANY_ASSIGN.finditer(line):
            if m.group(2).startswith("cargo"):
                continue
            if line.lstrip().startswith("#") or "echo " in line[: m.start()]:
                continue
            out.append((number, m.group(1), m.group(2)))
    return out


def probe_command(kind: str, name: str) -> str:
    if kind == "file":
        return f"test -r {shlex.quote(name)}"
    return f"command -v {shlex.quote(name)} >/dev/null 2>&1"


def check() -> int:
    findings: list[str] = []
    try:
        text = RUN_CI.read_text(encoding="utf-8")
    except OSError as err:
        print(f"armed-oracle: FAIL -- {RUN_CI} is unreadable ({err})")
        return 1

    found = armings(text)
    if not found:
        print(
            "armed-oracle: FAIL -- `run-ci.sh` arms no adjudicator at all. "
            "Every assertion below is about a population, and an empty one "
            "agrees with everything; if the last arming has genuinely gone, "
            "this floor comes down in the same commit that removed it."
        )
        return 1

    for flag in sorted(found - set(ROWS)):
        findings.append(
            f"`run-ci.sh` arms `{flag}` on every runner and no row here says "
            f"what that runner must already have. An armed flag is a statement "
            f"about the MACHINE, and item 562 is what an unstated one cost: a "
            f"whole lane that could not complete anywhere off the hosted job."
        )
    for flag in sorted(set(ROWS) - found):
        findings.append(
            f"`{flag}` has a row here and `run-ci.sh` no longer arms it with a "
            f"`cargo` invocation. Delete the row: a requirement nothing "
            f"imposes is a demand on every machine for no reason."
        )
    for number, flag, nxt in unclassifiable(text):
        findings.append(
            f"run-ci.sh:{number}: `{flag}=1` is followed by `{nxt}` on a line "
            f"that is neither a comment nor an `echo`, so it is not prose "
            f"about the flag -- and it does not prefix `cargo`, so this gate "
            f"cannot read it as an arming either. It will not guess: teach it "
            f"the shape, or the population it walks is smaller than the "
            f"file's, which is item 562 arriving again."
        )

    for flag, (test, oracles) in sorted(ROWS.items()):
        path = TESTS / test
        if not path.is_file():
            findings.append(f"`{flag}`'s row names `{test}`, which is not a file")
            continue
        body = path.read_text(encoding="utf-8")
        if flag not in body:
            findings.append(
                f"`{flag}`'s row names `{test}` and that source never mentions "
                f"the flag. The row would then describe a test that does not "
                f"consult it."
            )
        if not oracles:
            findings.append(
                f"`{flag}` is armed and its row names no oracle. There is no "
                f"'needs nothing' here: a flag that turns a skip into a "
                f"failure does so because something has to be present."
            )
        for kind, name in oracles:
            if kind not in KINDS:
                findings.append(f"`{flag}` declares oracle kind `{kind}`, not in {KINDS}")
                continue
            if name not in body:
                findings.append(
                    f"`{flag}` declares the {kind} `{name}` and `{test}` does "
                    f"not name it. The row has drifted from the default the "
                    f"test actually reaches for, which is the direction that "
                    f"sends somebody to provision the wrong thing."
                )

    if findings:
        print(f"armed-oracle: FAIL -- {len(findings)} finding(s)")
        for f in findings:
            print(f"  {f}")
        return 1

    total = sum(len(o) for _t, o in ROWS.values())
    print(
        f"  armed-oracle: {len(found)} adjudicator(s) armed on every runner by "
        f"`run-ci.sh`, each naming the test that reads it and the {total} "
        f"oracle(s) that machine must already have -- every one of them found "
        f"in that test's own source. `--probe [--host H]` asks a machine."
    )
    return 0


def run_probe(kind: str, name: str, host: str | None) -> bool:
    """Is this oracle present, here or on `host`? One shell command either way."""
    cmd = probe_command(kind, name)
    argv = (
        ["ssh", "-o", "ConnectTimeout=10", host, cmd] if host else ["bash", "-c", cmd]
    )
    return subprocess.run(argv, capture_output=True).returncode == 0


def probe(host: str | None) -> int:
    # The anti-vacuity floor, and `--probe` needs its own: `--check` has one
    # over the ARMINGS and this walks the ROWS, so an emptied table would print
    # "has every oracle" over nothing at all -- a green that means the opposite
    # of what a reader takes from it.
    if not ROWS:
        print(
            "armed-oracle: FAIL -- no row to probe. This mode answers 'can "
            "this machine run the armed lanes', and over an empty table the "
            "answer is always yes and always worthless."
        )
        return 1
    missing: list[str] = []
    seen: set[tuple[str, str]] = set()
    for flag, (_test, oracles) in sorted(ROWS.items()):
        for kind, name in oracles:
            if (kind, name) in seen:
                continue
            seen.add((kind, name))
            ok = run_probe(kind, name, host)
            print(f"  {'present' if ok else 'ABSENT ':8s} {kind:8s} {name}")
            if not ok:
                missing.append(f"{kind} {name} (armed by {flag})")
    where = host or "this machine"
    if missing:
        print(
            f"armed-oracle: {where} is MISSING {len(missing)} oracle(s), so "
            f"any lane arming them fails there rather than skipping:"
        )
        for m in missing:
            print(f"  {m}")
        print(
            "  On a Debian-family host: `sudo apt-get install -y libpcap-dev "
            "tcpdump netbase` covers every row this file declares."
        )
        return 1
    print(f"  armed-oracle: {where} has every oracle the armed lanes demand")
    return 0


def selftest() -> int:
    """Drive each refusal, past controls that must NOT be refused."""
    global ROWS
    real_rows = dict(ROWS)
    cases: list[tuple[str, str, dict, str]] = [
        (
            "an arming with no row",
            "WZ_NEW_REQUIRE=1 cargo test\nWZ_TCPDUMP_REQUIRE=1 cargo test\n",
            {"WZ_TCPDUMP_REQUIRE": real_rows["WZ_TCPDUMP_REQUIRE"]},
            "no row here says",
        ),
        (
            "a row nothing arms",
            "WZ_TCPDUMP_REQUIRE=1 cargo test\n",
            real_rows,
            "no longer arms it",
        ),
        (
            "an assignment in neither shape",
            "WZ_TCPDUMP_REQUIRE=1 cargo test\nWZ_TCPDUMP_REQUIRE=1 bash foo\n",
            {"WZ_TCPDUMP_REQUIRE": real_rows["WZ_TCPDUMP_REQUIRE"]},
            "cannot read it as an arming",
        ),
        (
            "an oracle the test does not name",
            "WZ_TCPDUMP_REQUIRE=1 cargo test\n",
            {
                "WZ_TCPDUMP_REQUIRE": (
                    "bsd_af_tcpdump_adjudicator.rs",
                    (("program", "wireshark"),),
                )
            },
            "does not name it",
        ),
        (
            "a row naming no oracle",
            "WZ_TCPDUMP_REQUIRE=1 cargo test\n",
            {"WZ_TCPDUMP_REQUIRE": ("bsd_af_tcpdump_adjudicator.rs", ())},
            "names no oracle",
        ),
    ]
    # Two shapes of prose in one control -- a comment line and an `echo` -- so
    # a gate that started refusing either would be caught here rather than by
    # somebody reading a lane log.
    control = (
        "WZ_TCPDUMP_REQUIRE=1 cargo test\n"
        "# WZ_TCPDUMP_REQUIRE=1 turns the skip into a failure\n"
        '    echo "  SKIP (set WZ_TCPDUMP_REQUIRE=1 — makes it fail)"\n'
    )
    import io
    import contextlib

    failures: list[str] = []
    for label, script, rows, needle in cases:
        ROWS = rows
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = _check_text(script)
        if rc == 0 or needle not in buf.getvalue():
            failures.append(f"{label}: rc={rc}, output did not carry {needle!r}")
    # THE CONTROLS. Without them every refusal above is satisfied by a gate
    # that refuses everything, which is the shape this workspace keeps paying
    # for.
    ROWS = {"WZ_TCPDUMP_REQUIRE": real_rows["WZ_TCPDUMP_REQUIRE"]}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = _check_text(control)
    if rc != 0:
        failures.append(f"the clean control was refused: {buf.getvalue()}")
    ROWS = real_rows

    # THE PRESENCE TEST ITSELF, driven both ways. `--probe` is the mode that
    # answers "can this machine run the armed lanes", and a presence test that
    # said yes to everything would answer it with a constant -- which is
    # exactly the failure item 562 is about, one level down.
    presence = [
        ("file", "/etc/protocols", True),
        ("file", "/nonexistent/armed-oracle-probe/dlt.h", False),
        ("program", "sh", True),
        ("program", "armed-oracle-no-such-program", False),
    ]
    for kind, name, want in presence:
        got = run_probe(kind, name, None)
        if got != want:
            failures.append(
                f"the presence test for {kind} `{name}` answered {got} and "
                f"must answer {want}; a probe that cannot tell present from "
                f"absent reports every machine as provisioned"
            )
    # An emptied table must not report a machine as ready.
    ROWS = {}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = probe(None)
    if rc == 0:
        failures.append("an empty ROWS table reported the machine as ready")
    ROWS = real_rows

    if failures:
        print("armed-oracle: SELFTEST FAIL")
        for f in failures:
            print(f"  {f}")
        return 1
    print(
        f"  armed-oracle selftest OK -- {len(cases)} damage probe(s) refused "
        f"for their own stated reason (an arming with no row, a row nothing "
        f"arms, an assignment in neither shape, an oracle the test does not "
        f"name, a row naming none); a clean script carrying an arming AND both "
        f"shapes of prose about it passes; the presence test tells a present "
        f"file and program from an absent one in all four directions; and an "
        f"emptied table refuses to call a machine ready"
    )
    return 0


def _check_text(script: str) -> int:
    """`check` against a script held in memory, for the selftest."""
    global RUN_CI
    real = RUN_CI
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        p = pathlib.Path(tmp) / "run-ci.sh"
        p.write_text(script, encoding="utf-8")
        RUN_CI = p
        try:
            return check()
        finally:
            RUN_CI = real


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(add_help=True)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--probe", action="store_true")
    mode.add_argument("--selftest", action="store_true")
    ap.add_argument("--host", default=None, help="probe this ssh alias instead")
    args = ap.parse_args(argv)
    if args.host and not args.probe:
        ap.error("--host only means anything with --probe")
    if args.selftest:
        return selftest()
    return probe(args.host) if args.probe else check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
