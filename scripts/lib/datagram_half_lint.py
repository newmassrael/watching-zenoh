#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y704 (§1.1n) — a walk over `flows()` must also walk the DATAGRAM half.

THE DEFECT THIS EXISTS FOR, four times measured and never once caught by a gate:

  R311y668  `--flows` listed no datagram flow at all.
  R311y678  the field layer walked stream flows only.
  R311y699  `--payload-format` reached one row producer.
  R311y700  `wz_analyze::samples` yielded ZERO samples for a datagram capture,
            and said nothing -- an empty plan is what an empty capture prints.

Every one was found by a person reading the code, and every one shipped first.
`Dissection::flows()` is the TCP half and `datagram_flows()` is the other one;
a reader who walks the first and forgets the second produces an EMPTY result
rather than an error, and an empty result is indistinguishable from a capture
that carried nothing.

WHY A STATIC SCAN. The invariant is "this function considered the other half",
which is a fact about the source. No build fails when it does not hold, and no
assertion can observe its own absence -- the same reason `solo_plane_page_lint`
and `literal_wire_flag_lint` read source rather than running anything.

WHAT IT IS NOT. It does not claim the datagram half is walked WELL, only that
the function names it. A body that mentioned `datagram_flows()` and did nothing
with it would satisfy this, and that is the honest limit of a scan.

It is also NOT the R311y699 shape. That defect was a plane reaching one of three
ROW PRODUCERS, all of which do walk both halves; this scan would have passed it.
The two failures are cousins and only one of them is mechanical.

THE OPT-OUT IS A REASON, NOT A LIST. A function that legitimately only concerns
the stream half says so in its own body with the marker below, which puts the
justification next to the code rather than in a table someone has to find.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# ONE copy of the "blank comments and string literals, keep offsets" rule, taken
# from the lint that already got it right. A second implementation would drift
# exactly where a brace inside a string literal runs a body walk off the end --
# which is a bug that scan already shipped and fixed.
from solo_plane_page_lint import blank_noncode  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

# The crate where all four defects landed. `wz-capture` owns both halves and is
# the crate a reader walks them FROM; the forgetting happens in the consumer.
CRATE = Path("crates/wz-analyze")

# The two halves.
STREAM = ".flows()"
DATAGRAM = "datagram_flows()"

# A body that calls a helper whose name says datagram has considered the half,
# even though the call to `datagram_flows()` is inside that helper.
DELEGATES = "datagram"

# The in-body opt-out. Deliberately verbose: a marker a person types by accident
# is a gate that turns itself off.
EXEMPT = "DATAGRAM-HALF-NOT-APPLICABLE"

# Below this the scan resolved the wrong root or read the wrong crate. A run
# that found nothing to look at must not report OK -- the failure mode
# `duplicate_module_lint` shipped with on its first run (0 files, exit 0).
MIN_FILES = 2


def walks(root: Path) -> tuple[list[tuple[str, str]], list[tuple[str, str]], int]:
    """`(offenders, exempted, files scanned)`, each entry `(file, fn)`."""
    offenders: list[tuple[str, str]] = []
    exempted: list[tuple[str, str]] = []
    scanned = 0
    for path in sorted((root / CRATE).rglob("*.rs")):
        if "target" in path.parts:
            continue
        scanned += 1
        raw = path.read_text(encoding="utf-8", errors="replace")
        # The EXEMPT marker is deliberately read from the RAW text: it is meant
        # to be written as a comment beside the reason, and blanking comments
        # would make it unwritable in the only place it belongs.
        masked = blank_noncode(raw).splitlines()
        rawlines = raw.splitlines()
        i = 0
        while i < len(masked):
            line = masked[i]
            stripped = line.lstrip()
            if not (stripped.startswith("fn ") or stripped.startswith("pub fn ")):
                i += 1
                continue
            name = stripped.split("(")[0].split()[-1]
            depth = 0
            opened = False
            k = i
            body: list[str] = []
            raw_body: list[str] = []
            while k < len(masked):
                body.append(masked[k])
                raw_body.append(rawlines[k] if k < len(rawlines) else "")
                depth += masked[k].count("{") - masked[k].count("}")
                opened = opened or "{" in masked[k]
                if opened and depth <= 0:
                    break
                k += 1
            text = "\n".join(body)
            i = k + 1
            if STREAM not in text:
                continue
            if DATAGRAM in text or DELEGATES in text:
                continue
            if EXEMPT in "\n".join(raw_body):
                exempted.append((path.name, name))
                continue
            offenders.append((path.name, name))
    return offenders, exempted, scanned


def main() -> int:
    offenders, exempted, scanned = walks(REPO_ROOT)

    if scanned < MIN_FILES:
        print(
            f"datagram-half lint: FAIL — scanned {scanned} file(s) under {CRATE}, "
            f"fewer than the {MIN_FILES} that tree has. A checker that found "
            f"nothing to read must not report OK.",
            file=sys.stderr,
        )
        return 1

    if offenders:
        print("datagram-half lint: FAIL", file=sys.stderr)
        for where, fn in offenders:
            print(f"  {where}::{fn} walks flows() and never names the other half", file=sys.stderr)
        print(
            "\n`Dissection::flows()` is the TCP half. A function that walks it "
            "and not\n`datagram_flows()` returns an EMPTY result over a "
            "multicast or scouting\ncapture, which reads exactly like a capture "
            "that carried nothing. This has\nshipped four times: R311y668, "
            "R311y678, R311y699, R311y700.\n\nWalk the other half, delegate to "
            "a helper whose name says `datagram`, or --\nif this function "
            f"genuinely only concerns the stream half -- write\n`{EXEMPT}` in "
            "its body beside the reason.",
            file=sys.stderr,
        )
        return 1

    note = f", {len(exempted)} exempted" if exempted else ""
    print(
        f"datagram-half lint: OK (every flows() walk under {CRATE} names the "
        f"other half{note}; {scanned} file(s))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
