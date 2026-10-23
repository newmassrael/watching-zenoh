#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y581 (no register item) — the UNWIRED-LANE gate.

A lane registered in `scripts/run-ci.sh` but absent from
`.github/workflows/ci.yml`'s `--layer` set runs ONLY in a local full sweep.
That is a hazard the workflow's own comments already name three separate
times, in three separate jobs, each time about a different lane -- and nothing
ever checked it.

The diff found SEVEN: `C1as`, `C1az`, `C1be`, `C1bh`, `E7b`, `E7c`, and
`C1bn`. The last one is the reason this is a gate rather than a fourth
comment: R311y579 created it in the same round that CLOSED the "wz-capture and
transport-link-tls-keylog are in no lane at all" debt. Closing one hole while
opening another is not closing it, and prose in the workflow had already
failed to prevent that three times.

DIRECTION IS DELIBERATE, run-ci.sh -> ci.yml only. The reverse would fire on
every workflow step that is not a `run_layer` -- checkout, toolchain install,
caching, the disk-headroom report -- none of which is a defect.

A deliberate absence is expressible: delete the lane's `run_layer` line. A
lane nobody runs anywhere is a different (and louder) statement than a lane
the hosted gate silently never reaches.
"""

import pathlib
import re
import sys

RUN_LAYER = re.compile(r"(?m)^run_layer ([A-Za-z0-9]+) ")
CI_LAYER = re.compile(r"--layer ([A-Za-z0-9]+)")


def main() -> int:
    runci_path = pathlib.Path("scripts/run-ci.sh")
    ciyml_path = pathlib.Path(".github/workflows/ci.yml")
    for path in (runci_path, ciyml_path):
        if not path.is_file():
            # A gate that cannot read its input must not report green.
            print(f"unwired-lane lint FAIL: {path} not found (wrong cwd?)", file=sys.stderr)
            return 1

    registered_ids = RUN_LAYER.findall(runci_path.read_text())
    registered = set(registered_ids)
    wired = set(CI_LAYER.findall(ciyml_path.read_text()))

    if not registered:
        print(
            "unwired-lane lint FAIL: no `run_layer` lines matched; the pattern "
            "has drifted from run-ci.sh and this check asserted nothing",
            file=sys.stderr,
        )
        return 1

    # R3464 -- ONE ID, ONE LANE. `--layer X` runs every `run_layer X` line, so a
    # second registration under a taken id does not fail anywhere: it makes the
    # two lanes run together under one name, and the set difference below, which
    # reads ids and not lanes, reports the new one as wired because the old one
    # is. That is how `C1bw` was given to a second lane and passed this lint.
    duplicated = sorted({lane for lane in registered_ids if registered_ids.count(lane) > 1})
    if duplicated:
        print("Layer C0 FAIL: lane id(s) registered more than once in run-ci.sh:", file=sys.stderr)
        for lane in duplicated:
            print(f"    - {lane}", file=sys.stderr)
        print("", file=sys.stderr)
        print("  `--layer <id>` runs every lane under that id, so the second one", file=sys.stderr)
        print("  rides the first one's job unseen. Give it an id of its own.", file=sys.stderr)
        return 1

    missing = sorted(registered - wired)
    if missing:
        print("Layer C0 FAIL: lane(s) registered in run-ci.sh but NOT in ci.yml:", file=sys.stderr)
        for lane in missing:
            print(f"    - {lane}", file=sys.stderr)
        print("", file=sys.stderr)
        print("  Each runs only in a local full sweep, so hosted CI never", file=sys.stderr)
        print("  executes it. Wire it into the job whose provisioning it needs,", file=sys.stderr)
        print("  or -- if the absence is deliberate -- remove its run_layer line.", file=sys.stderr)
        return 1

    print(f"  unwired-lane gate: {len(registered)} registered lane(s), 0 absent from ci.yml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
