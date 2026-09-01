#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2240 (no register item) — a foreign oracle this tree BUILT can fall behind
the version this tree PINS, and nothing measured that.

The citation is `no register item` in the sense `debt_plane_census.py` uses:
item 592 lives in the agent-memory register, which has no store id for
`gate_provenance_lint.py` to resolve. The item is named in prose here.

## The defect, measured

`scripts/build-zenohd.sh:46` pins `ZENOHD_VERSION="${ZENOHD_VERSION:-1.10.0}"`
(R2228 moved it there from 1.5.0). The binaries it installs are gitignored
build output, so moving the constant moves NOTHING on a machine that already
has them — and on 2026-09-01 three of this tree's four oracles were still the
old version:

    target/zenohd            v1.10.0   (rebuilt 2026-08-31)
    target/zenohd-unixpipe   v1.5.0    (built 2026-07-21)
    target/zenohd-vsock      v1.5.0    (built 2026-07-23)
    target/zenohd-shm        v1.5.0    (built 2026-08-02)

The SHM one was found the expensive way. `wz_shm_establishment_zenohd_interop`
was GREEN against the v1.5.0 binary and goes RED the moment the oracle is built
at the pin — so the lane had been reporting on a version the tree no longer
claims to target, and the finding arrived from a different repository's session
provisioning its own oracle rather than from anything here. The other two were
found by this file's first run, which is the whole argument for it: the class
is "the oracle is stale", not "the SHM oracle is stale", and a check written
for the instance that hurt would have left two behind.

## Why the version has to come from the BINARY

`--version` is the binary's own answer. Every cheaper reading is a claim about
it made by something else:

  * the mtime says when a file was written, not what is in it;
  * the cache key in `ci.yml` says what the runner MEANT to restore — R2228's
    note that "a cache key naming the old version restores the old binary under
    the new pin" is exactly this failure with the label attached;
  * `zenoh-cargo-metadata.json`, which `build-zenohd.sh` installs beside SOME
    of the binaries, is written by the same run — but only two of the four
    directories have one, so it cannot be the primary reading. It is used here
    as a SECOND axis where it exists (a metadata file that disagrees with the
    binary it sits next to means one of the two was replaced alone), and its
    absence is never a pass: the binary axis has already judged that oracle.

## What it derives rather than declares

  * THE POPULATION is every `INSTALL_DIR="$ROOT/target/…"` assignment in
    `build-zenohd.sh`. Four today. A fifth variant added there is covered the
    day it is added, with no edit here — and a population of zero is a HARD
    FAIL, because a gate that found no subjects must not report a pass.
  * THE PIN is that script's `ZENOHD_VERSION` default. Not a copy.

## The classification, and why "absent" is not a pass

Every oracle lands in exactly one class, and the two that are not OK are RED:

    MATCH      the binary answers with the pinned version
    STALE      it answers with something else                          -> RED
    UNREADABLE it is there and will not say                            -> RED
    ABSENT     this host never built it

ABSENT is the honest state on hosted CI, which provisions `zenohd`,
`zenohd-unixpipe` and `zenohd-vsock` but never `zenohd-shm` (no `ZENOHD_SHM` in
any workflow), and on a fresh clone, which has none. It is NOT silence: the
count is printed, so "this host checked nothing" can never read as "this host
found nothing wrong". `--require` turns a fully absent population into a
failure, which is what a lane that has just built an oracle should pass.

`--require` is an ARGUMENT and deliberately not a `WZ_..._REQUIRE=1` environment
prefix. That spelling is spoken for: `armed_oracle_census.py` owns it, and what
it owns is the mapping from an INTEGRATION TEST's skip-adjudicator to a failure,
with a table whose every row names a test file and oracle strings that must
occur in that test's own source. This gate is not a test and it derives its
oracles from `build-zenohd.sh` rather than naming them, so a row for it could
only be written by hardcoding the four paths — the one thing the derivation
above exists to avoid. An argument says the same thing at the call site, in the
open, and leaves that census's population exactly what it claims to be.

UNREADABLE exists because the alternative is the trap this gate is about. A
binary that cannot be executed, times out, or prints a line no version can be
parsed from is a binary whose version is UNKNOWN, and unknown is not match.
"""

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import typing

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD_SCRIPT = ROOT / "scripts" / "build-zenohd.sh"

# `INSTALL_DIR="$ROOT/target/zenohd-shm"` and friends. Anchored on the
# assignment so a mention of the path in a comment cannot enlarge the set.
INSTALL_DIR_RE = re.compile(r'^\s*INSTALL_DIR="\$ROOT/(target/[A-Za-z0-9._-]+)"', re.M)
# `ZENOHD_VERSION="${ZENOHD_VERSION:-1.10.0}"`
PIN_RE = re.compile(r'^\s*ZENOHD_VERSION="\$\{ZENOHD_VERSION:-([^}"]+)\}"', re.M)
# `zenohd v1.10.0 built with rustc 1.97.1 (…)`. The version token is NOT
# assumed to be semver: a zenohd built from an untagged checkout reports its
# commit hash there (`v49c8a538`), and that is a version this tree does not
# pin, which is precisely the answer STALE should give.
VERSION_RE = re.compile(r"\bzenohd v(\S+)")

MATCH, STALE, UNREADABLE, ABSENT = "MATCH", "STALE", "UNREADABLE", "ABSENT"


def population(script_text: str) -> list[str]:
    """Every oracle install directory the build script can produce."""
    dirs: list[str] = []
    for m in INSTALL_DIR_RE.finditer(script_text):
        if m.group(1) not in dirs:
            dirs.append(m.group(1))
    return dirs


def pin(script_text: str) -> str:
    m = PIN_RE.search(script_text)
    if not m:
        raise SystemExit(
            "oracle-pin-gate: FAIL -- no `ZENOHD_VERSION=\"${ZENOHD_VERSION:-…}\"` "
            f"default in {BUILD_SCRIPT}. The pin is this gate's only reference; "
            "without it every reading below would be compared against nothing."
        )
    return m.group(1).strip()


def binary_version(binary: pathlib.Path) -> str | None:
    """What the binary itself says, or None when it will not say."""
    try:
        proc = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for stream in (proc.stdout, proc.stderr):
        m = VERSION_RE.search(stream or "")
        if m:
            return m.group(1)
    return None


def metadata_version(meta: pathlib.Path) -> str | None:
    """The `zenoh` package version recorded beside the binary, when there is one.

    A SECOND axis, never a substitute: only two of the four directories carry
    this file, so its absence says nothing about the oracle -- the binary axis
    has already judged it.
    """
    try:
        doc = json.loads(meta.read_text())
    except (OSError, ValueError):
        return None
    for pkg in doc.get("packages", []):
        if pkg.get("name") == "zenoh":
            v = pkg.get("version")
            return str(v) if v else None
    return None


class Finding(typing.NamedTuple):
    directory: str
    verdict: str
    detail: str


def inspect(root: pathlib.Path, rel_dir: str, pinned: str) -> Finding:
    binary = root / rel_dir / "zenohd"
    if not binary.exists():
        return Finding(rel_dir, ABSENT, "not built on this host")
    if not os.access(binary, os.X_OK):
        return Finding(rel_dir, UNREADABLE, "present but not executable")
    got = binary_version(binary)
    if got is None:
        return Finding(rel_dir, UNREADABLE, "`--version` printed no `zenohd v…` line")
    if got != pinned:
        return Finding(rel_dir, STALE, f"binary says {got}, pin says {pinned}")
    meta = root / rel_dir / "zenoh-cargo-metadata.json"
    if meta.exists():
        mv = metadata_version(meta)
        if mv is None:
            return Finding(
                rel_dir,
                UNREADABLE,
                "zenoh-cargo-metadata.json carries no `zenoh` package version",
            )
        if mv != got:
            return Finding(
                rel_dir,
                STALE,
                f"binary says {got} but its own metadata says {mv} -- "
                "one of the two was replaced alone",
            )
    return Finding(rel_dir, MATCH, f"v{got}")


def run(root: pathlib.Path, script_text: str, require: bool) -> int:
    pinned = pin(script_text)
    dirs = population(script_text)
    if not dirs:
        raise SystemExit(
            "oracle-pin-gate: FAIL -- derived ZERO oracle directories from "
            f"{BUILD_SCRIPT}. A population of zero reports green by "
            "construction, which is the shape this gate exists to refuse."
        )
    findings = [inspect(root, d, pinned) for d in dirs]
    bad = [f for f in findings if f.verdict in (STALE, UNREADABLE)]
    present = [f for f in findings if f.verdict != ABSENT]
    absent = [f for f in findings if f.verdict == ABSENT]

    for f in findings:
        print(f"  oracle-pin-gate: {f.verdict:<10} {f.directory} -- {f.detail}")
    print(
        f"  oracle-pin-gate: pin {pinned}; derived {len(dirs)} oracle(s), "
        f"{len(present)} present, {len(absent)} absent, {len(bad)} off the pin"
    )

    if bad:
        print(
            "  oracle-pin-gate: FAIL -- an oracle this tree builds does not "
            "answer with the pinned version. Rebuild it AT THE PIN "
            "(`ZENOHD_SRC=<a checkout at the pin> bash scripts/build-zenohd.sh`, "
            "with ZENOHD_UNIXPIPE=1 / ZENOHD_VSOCK=1 / ZENOHD_SHM=1 for the "
            "variants); do NOT move the pin to match a binary, which is the "
            "direction that erases what the lanes are measuring.",
            file=sys.stderr,
        )
        return 1
    if not present:
        msg = (
            "  oracle-pin-gate: no oracle is built on this host, so this run "
            "checked NOTHING -- that is a skip, not a pass."
        )
        if require:
            print(msg, file=sys.stderr)
            print(
                "  oracle-pin-gate: FAIL -- --require was given and the "
                "population is empty.",
                file=sys.stderr,
            )
            return 1
        print(msg)
    return 0


def selftest() -> int:
    """Drive every class, and prove the gate FAILS on the ones that must fail.

    The fixtures are the shapes an earlier reading would have swallowed: a
    binary that is present and OLD (the SHM case as it actually stood), one
    that is present and mute, and one whose metadata disagrees with itself.
    """
    fake_script = (
        'ZENOHD_VERSION="${ZENOHD_VERSION:-9.9.9}"\n'
        'INSTALL_DIR="$ROOT/target/ok"\n'
        'INSTALL_DIR="$ROOT/target/old"\n'
        'INSTALL_DIR="$ROOT/target/mute"\n'
        'INSTALL_DIR="$ROOT/target/gone"\n'
        'INSTALL_DIR="$ROOT/target/meta-disagrees"\n'
        '# INSTALL_DIR="$ROOT/target/a-comment-must-not-count"\n'
    )
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)

        def stub(name: str, line: str | None) -> pathlib.Path:
            d = root / "target" / name
            d.mkdir(parents=True)
            b = d / "zenohd"
            body = "#!/bin/sh\n" + (f'echo "{line}"\n' if line else "echo nothing\n")
            b.write_text(body)
            b.chmod(0o755)
            return d

        stub("ok", "zenohd v9.9.9 built with rustc 1.97.1")
        stub("old", "zenohd v1.5.0 built with rustc 1.85.0")
        stub("mute", None)
        d = stub("meta-disagrees", "zenohd v9.9.9 built with rustc 1.97.1")
        (d / "zenoh-cargo-metadata.json").write_text(
            json.dumps({"packages": [{"name": "zenoh", "version": "1.5.0"}]})
        )

        dirs = population(fake_script)
        if dirs != ["target/ok", "target/old", "target/mute", "target/gone",
                    "target/meta-disagrees"]:
            failures.append(f"population derived {dirs}; a comment leaked or an entry was lost")
        if pin(fake_script) != "9.9.9":
            failures.append("pin was not derived from the script")

        want = {
            "target/ok": MATCH,
            "target/old": STALE,
            "target/mute": UNREADABLE,
            "target/gone": ABSENT,
            "target/meta-disagrees": STALE,
        }
        for rel, expected in want.items():
            got = inspect(root, rel, "9.9.9").verdict
            if got != expected:
                failures.append(f"{rel}: expected {expected}, got {got}")

        # The whole run must FAIL on this fixture -- a gate that classifies
        # correctly and then exits 0 has classified nothing.
        if run(root, fake_script, require=False) == 0:
            failures.append("run() returned 0 with a STALE oracle in the population")

        # And it must PASS when only the good one is present, so the failure
        # above is attributable to the stale entry rather than to the fixture.
        only_ok = 'ZENOHD_VERSION="${ZENOHD_VERSION:-9.9.9}"\nINSTALL_DIR="$ROOT/target/ok"\n'
        if run(root, only_ok, require=False) != 0:
            failures.append("run() failed on a population whose single oracle matches")

        # An empty-but-derived population is a skip, and a FAIL when armed.
        empty = 'ZENOHD_VERSION="${ZENOHD_VERSION:-9.9.9}"\nINSTALL_DIR="$ROOT/target/gone"\n'
        if run(root, empty, require=False) != 0:
            failures.append("an all-absent population should skip, not fail, unarmed")
        if run(root, empty, require=True) == 0:
            failures.append("--require did not fail an empty population")

        # No population at all is a hard fail, not a green.
        try:
            run(root, 'ZENOHD_VERSION="${ZENOHD_VERSION:-9.9.9}"\n', require=False)
            failures.append("a zero-oracle script did not hard-fail")
        except SystemExit:
            pass

    for f in failures:
        print(f"  oracle-pin-gate: SELFTEST FAIL -- {f}", file=sys.stderr)
    if failures:
        return 1
    print("  oracle-pin-gate: selftest passed (5 classes, both verdicts, armed and not)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="oracle_pin_gate.py",
        description="Every zenohd oracle this tree builds must answer with the pinned version.",
    )
    ap.add_argument("--check", action="store_true", help="read the real tree (default)")
    ap.add_argument("--selftest", action="store_true", help="drive the classes against fixtures")
    ap.add_argument(
        "--require",
        action="store_true",
        help="a population with no oracle present is a FAIL, not a skip",
    )
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not BUILD_SCRIPT.exists():
        raise SystemExit(f"oracle-pin-gate: FAIL -- {BUILD_SCRIPT} is missing")
    return run(ROOT, BUILD_SCRIPT.read_text(), require=args.require)


if __name__ == "__main__":
    sys.exit(main())
