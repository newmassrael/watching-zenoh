#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2079 (no register item) — is `DEEPENABLE_UPSTREAM_KEYS` COMPLETE?

It answers for open-debt item 502, which lives in the agent-memory register
OUTSIDE this tree and therefore has no `debt-` id to cite — the same position
`debt_plane_census.py` records for itself.

## The question this answers, and the one it does not

`wz_reads_a_stock_zenohd_config`'s LEG 9 asks a real zenohd about every key the
constant NAMES. That protects the entries. It cannot see a key the constant is
MISSING, and that is the dangerous direction: a key wrongly off the list makes wz
refuse a file a real zenohd starts on, and the only detection path left is an
operator reporting that their node will not come up.

This script asks the other question. It walks the WHOLE upstream surface --
`HONOURED_CONFIG_KEYS` + `UNHONOURED_UPSTREAM_CONFIG_KEYS` -- hands each key a
deeper shape, and classifies the key by what zenohd ANSWERS. Run it in any round
that moves the surface or the exception list.

MEASURED when it was written: it found `listen/retry` accepting a deeper shape
and absent from the list, which R2078 had introduced and no test could see.

## Why the probe needs no per-key value knowledge

Every key gets `{ zzz_not_a_mode: 1 }`, which is not a mode name and not a valid
value for anything. The classification is the MESSAGE, not the exit code:

  * the process comes up                       -> the subtree is OPAQUE
  * "expected one of `router`, `peer`, `client`" -> the key is MODE-DEPENDENT
  * anything else                               -> the key takes no deeper shape

⛔ Reading the message rather than the status is the whole method. Six probes in
the round that built the list came back "refused" and were DEAD -- four because
the fixture restated a key its own document already had (`duplicate field`), two
because the value shape was wrong. An exit code cannot tell a negative result
from a broken probe.

⚠ ONE KEY IS A KNOWN DEAD PROBE HERE, and it is named rather than silently
excused: `plugins` answers `plugins.zzz_not_a_mode must be object` -- a complaint
about the VALUE, not about the name -- while `plugins: { rest: { zzz: 1 } }`
starts. It is reported as UNDECIDED so the reader is told, not told nothing.

## Why this is NOT wired into a CI layer

Its oracle is `target/zenohd/zenohd`, which no clone and no CI runner has (the
same reason `debt_plane_census.py` stays local). A gate whose input is absent
must FAIL rather than skip, so hosting it would red every run. It exits 2 when
the binary is missing, and is a LOCAL instrument until that changes.

Usage:
    python3 scripts/lib/deepenable_audit.py [--verbose]
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "crates" / "wz-runtime-tokio" / "src" / "zenoh_config.rs"
# R2080 — the same override the test harness reads (`zenohd_binary()`), so the
# lane and this script cannot end up asking two different binaries.
ZENOHD = pathlib.Path(
    os.environ.get("WZ_ZENOHD_BIN") or REPO_ROOT / "target" / "zenohd" / "zenohd"
)

MODE_TABLE_MARKER = "expected one of `router`, `peer`, `client`"
STARTED_MARKER = "Zenoh can be reached at"
RESOLVED_MARKER = "Initial conf:"

# The one key whose generic probe is answered about its VALUE rather than its
# shape. See the module doc: naming it is the point.
UNDECIDABLE_BY_THIS_PROBE = {"plugins"}


def rust_const(name: str) -> list[str]:
    """Read a `&[&str]` constant out of the reader's own source.

    R2083 — COMMENT LINES ARE DROPPED FIRST, and that is not tidiness. These
    constants carry long `//` rationales between their entries, and several of
    those quote a phrase: `"wz cannot do this"`, `"the reader does not read
    this"`. A string sweep that does not strip comments reads PROSE AS DATA —
    measured, it turned `HONOURED_CONFIG_KEYS`'s 30 entries into 35 and put a
    wrong surface number into this project's own notes for a round. The floors
    below could not catch it: counting too MANY passes every one of them.
    """
    src = SOURCE.read_text()
    m = re.search(r"(?:pub )?const " + name + r": &\[&str\] = &\[(.*?)\n\];", src, re.S)
    if not m:
        raise SystemExit(f"deepenable-audit: FAIL -- {name} not found in {SOURCE}")
    body = "\n".join(
        line for line in m.group(1).splitlines() if not line.strip().startswith("//")
    )
    return re.findall(r'"([^"]+)"', body)


def document_for(key: str) -> str:
    """`{ mode: "peer", <key as nested objects>: { zzz_not_a_mode: 1 } }`."""
    if key == "mode":
        return '{ mode: { zzz_not_a_mode: 1 } }'
    inner = "{ zzz_not_a_mode: 1 }"
    for seg in reversed(key.split("/")):
        inner = "{ %s: %s }" % (seg, inner)
    return '{ mode: "peer", %s }' % inner[1:-1].strip()


def verdict_for(key: str, workdir: pathlib.Path) -> str:
    """Run one probe, and STOP as soon as the answer is on the page.

    R2080 — the first cut let `subprocess.run` hit a fixed timeout, so every key
    whose subtree is opaque cost the whole timeout instead of the ~60ms it takes
    zenohd to print its resolved config. Waiting for a deadline that has already
    been answered is not caution, it is just slower; the refusals still cost what
    zenohd's own startup costs, and that part is not ours to shorten.
    """
    config = workdir / "probe.json5"
    config.write_text(document_for(key) + "\n")
    log = workdir / "probe.log"
    accepted = False
    with open(log, "wb") as sink:
        proc = subprocess.Popen(
            [str(ZENOHD), "-c", str(config), "--rest-http-port", "none"],
            stdout=sink,
            stderr=sink,
        )
        deadline = time.monotonic() + 30.0
        while True:
            blob = log.read_text(errors="replace")
            if STARTED_MARKER in blob or RESOLVED_MARKER in blob:
                accepted = True
                break
            if proc.poll() is not None:
                break
            if time.monotonic() > deadline:
                break
            time.sleep(0.02)
        if proc.poll() is None:
            proc.kill()
        proc.wait()

    if accepted:
        return "OPAQUE"
    blob = log.read_text(errors="replace")
    if MODE_TABLE_MARKER in blob:
        return "MODE_TABLE"
    return "REFUSED"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not ZENOHD.is_file():
        print(
            f"deepenable-audit: FAIL -- no zenohd at {ZENOHD}. This audit's whole "
            f"content is what UPSTREAM answers, so an absent oracle is a failure "
            f"and not a skip. Run scripts/build-zenohd.sh.",
            file=sys.stderr,
        )
        return 2

    surface = sorted(
        set(rust_const("HONOURED_CONFIG_KEYS"))
        | set(rust_const("UNHONOURED_UPSTREAM_CONFIG_KEYS"))
    )
    declared = set(rust_const("DEEPENABLE_UPSTREAM_KEYS"))
    # R2080 — FLOORS, not just non-emptiness. The constants are read out of Rust
    # by regex, so a reformat that split one of them differently would be read
    # PARTIALLY, and a partial read PASSES: fewer keys probed, nothing said. That
    # is "a population of zero is green" in its quieter form. The floors sit far
    # below the measured 116 / 17, so ordinary movement of the surface does not
    # touch them and only a broken read can reach them.
    if len(surface) < 100:
        raise SystemExit(
            f"deepenable-audit: FAIL -- read only {len(surface)} surface key(s) out "
            f"of {SOURCE.name}. The constant moved, so this sweep is measuring a "
            f"fraction of the surface while reporting on all of it."
        )
    if len(declared) < 10:
        raise SystemExit(
            f"deepenable-audit: FAIL -- read only {len(declared)} deepenable key(s). "
            f"A partial read of the exception list makes every key it lost look "
            f"like a missing entry."
        )

    accepts: set[str] = set()
    undecided: set[str] = set()
    with tempfile.TemporaryDirectory() as tmp:
        workdir = pathlib.Path(tmp)
        for key in surface:
            verdict = verdict_for(key, workdir)
            if key in UNDECIDABLE_BY_THIS_PROBE:
                undecided.add(key)
            elif verdict in ("OPAQUE", "MODE_TABLE"):
                accepts.add(key)
            if args.verbose:
                print(f"  {key:48s} {verdict}")

    missing = sorted(accepts - declared)
    stale = sorted(declared - accepts - undecided)

    for key in missing:
        print(
            f"  deepenable-audit: {key} accepts a deeper shape and is NOT in "
            f"DEEPENABLE_UPSTREAM_KEYS. wz REFUSES a file zenohd starts on."
        )
    for key in stale:
        print(
            f"  deepenable-audit: {key} is in DEEPENABLE_UPSTREAM_KEYS and refuses "
            f"a deeper shape. wz accepts a typo zenohd would catch."
        )
    for key in sorted(undecided):
        print(
            f"  deepenable-audit: {key} UNDECIDED -- this probe's value is wrong "
            f"for it, not its shape. Judge it by hand."
        )

    print(
        f"  deepenable-audit: surface {len(surface)}, declared {len(declared)}, "
        f"measured accepting {len(accepts)}, undecided {len(undecided)}"
    )
    return 1 if missing or stale else 0


if __name__ == "__main__":
    sys.exit(main())
