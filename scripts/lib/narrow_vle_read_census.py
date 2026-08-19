#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y879 (no register item) — the NARROW VLE READ census.

Closes a defect found in its own round rather than a listed store item. The
open-debt numbers it touches live in the unregistered half of the register:
335 was the `weight` MISMATCH it carried (CLOSED R311y880), and 338 is the axis
it does NOT reach — nothing re-checks an ADJUDICATED verdict against upstream
after it is written, so a row can be right the day it lands and wrong after a
version bump without anything saying so.

R311y880 also refuted this file's own stated reason for carrying 335. The row
said closing it "needs an SCE capability or a different codegen model, not an
scxml retype", because SCE derives the read width from the storage type and
there is no wide-read/narrow-store form to declare. Both halves of that are
true and the conclusion still did not follow: the scxml declares the WIRE
width, and the value width belongs at the consumer boundary, so retyping the
field `uint64` and truncating once by name
(`wire_const::linkstate_weight_from_wire`) is exactly upstream's own model —
`uint_impl!(u16)` reads a full ZInt and casts. An adjudication's REASON can be
wrong in a direction that shuts a door (open-debt item 47), and this is the
instance that was written down inside the gate meant to prevent it.

## The class this exists for

A zint field whose value type is narrower than `u64` can be read two ways, and
upstream picks between them PER FIELD:

    Zenoh080Bounded<uN>   REFUSES a value that does not fit  (zenoh-codec/src/
                          core/zint.rs, `zint_impl_codec!`: `if (x & !MAX) != 0
                          { return Err(DidntRead) }`)
    Zenoh080 (plain)      TRUNCATES it                       (same file,
                          `uint_impl!`: `let x: u64 = self.read(reader)?;
                          Ok(x as $uint)`)

wz has exactly one reader of each shape (`SpanCursor::vle_u16` refuses,
`SpanCursor::vle_u16_truncated` truncates; `SceCursor::read_vle_uN` refuses),
and picking the wrong one is not a rendering nicety:

  * refuse where upstream truncates -> wz answers `Err` on a message the whole
    network reads to the end. In `parse_inbound_consuming` an `Err` consumes
    nothing, so the batch walk STOPS and every message behind it is lost.
  * truncate-less where upstream truncates -> wz reports a value no peer
    computes, and when the field SELECTS behaviour (the OAM id selects the
    linkstate body walk) wz acts differently from every conforming peer.

## Why a gate rather than care

The class has leaked three times, each found by hand and none by a test:

    R311y597  `weight` read narrow; upstream reads it plain    (fixed R311y880)
    R311y878  transport OAM `id` read narrow; upstream plain   (fixed R311y879)
    R311y879  network OAM `id` read wide, never truncated      (fixed R311y879)

Nothing compared wz's reader choice against upstream's codec choice, so the
fourth instance would have been found by hand too. This census is the
comparison: every narrow VLE read in wz-owned Rust must appear in ADJUDICATED
below with the upstream codec that decides it.

## What it pins, and what it does not

It pins the SET, not a count -- a count moves for two different reasons and
says which neither. A site that is absent from the table is a narrow read
nobody adjudicated; a table row with no site is an adjudication that has
outlived its code (the shape debt item 47 names). Both are FAIL.

It does NOT decide whether an entry's verdict is TRUE. `MISMATCH` rows are
carried deliberately, the same way `KNOWN_DIVERGENCES` carries pico's, so this
gate is green while the disagreement stays named. Whether wz should agree is a
round's judgement, not a scan's.

`vle_u16_truncated` is deliberately NOT censused: it reads `read_vle_u64` and
narrows afterwards, which is upstream's plain shape, so it is not a narrow
read. That is also why adding a truncating site never needs a table edit --
the gate is asked about the reader that can REFUSE.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# The trees whose Rust wz owns the reader choice in. `vendor/` is excluded
# because SCE's runtime is where `read_vle_uN` is DEFINED -- a definition is
# not a field, and wz does not choose there.
TREES = ("crates", "out")

# `read_vle_u16(` / `.vle_u32(` / ... — every reader that can answer
# `VleWidthOverflow`. `read_vle_u64` is absent on purpose: nothing is narrower
# than the wire's own maximum.
CALL = re.compile(r"\b(?:self\.cur\.|cursor\.|c\.)?(read_vle_u(?:8|16|32)|vle_u(?:8|16|32))\(")
ARG = re.compile(r"\(\s*\"([^\"]+)\"")
FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+|async\s+|unsafe\s+)*fn\s+([A-Za-z0-9_]+)")

# site key -> (verdict, why). The key is `<path>::<enclosing fn>::<field>`:
# a path and a NAME, never a line number, because a line number goes stale on
# an edit that changes nothing this gate is about.
#
# verdict is what UPSTREAM does, not what wz does:
#   REFUSE    upstream reads it through `Zenoh080Bounded<uN>` -- a narrow read
#             is the faithful one.
#   MISMATCH  upstream reads it plain (truncating) and wz still reads it
#             narrow. Carried, named, and owed to a register item.
ADJUDICATED: dict[str, tuple[str, str]] = {
    "crates/wz-session-core/src/dissect.rs::vle_u16::": (
        "REFUSE",
        "the PRIMITIVE, not a field: `SpanCursor::vle_u16` is the refusing "
        "reader itself. It has NO call site as of R311y880 -- `weight` was its "
        "last one and upstream truncates there -- and it is kept because "
        "`Zenoh080Bounded<u16>` is a real upstream shape whose u32 sibling "
        "decides `Encoding.id`. A new call site reds this gate until someone "
        "names the upstream codec for that field, which is the point.",
    ),
    "crates/wz-session-core/src/dissect.rs::vle_u32::": (
        "REFUSE",
        "the PRIMITIVE, as above -- `SpanCursor::vle_u32`.",
    ),
    "crates/wz-session-core/src/dissect.rs::walk_encoding::packed_id": (
        "REFUSE",
        "`Encoding.id` is written AND read through `Zenoh080Bounded::<u32>` "
        "(zenoh-codec/src/core/encoding.rs:47 and :64-65), so upstream itself "
        "answers `DidntRead` on a value past u32. The narrow read is right "
        "here, and this row is the CONTROL that keeps the gate from reading "
        "as `every narrow read is a bug`.",
    ),
    "out/wz-codecs/encoding.rs::decode::": (
        "REFUSE",
        "the generated sibling of `walk_encoding` above, and correct for the "
        "same reason: upstream's `Encoding` codec is `Zenoh080Bounded::<u32>` "
        "on both sides.",
    ),
}


def tracked_rust() -> list[Path]:
    """Every tracked `.rs` under the censused trees, per git.

    git rather than a glob so a build artifact or an untracked scratch file
    can never join the population -- the same reason the exclusion-integrity
    axis reads the VCS instead of the filesystem.
    """
    cmd = ["git", "-C", str(ROOT), "ls-files", "--", *(f"{t}/**/*.rs" for t in TREES)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"`git ls-files` failed (rc={proc.returncode}): "
            f"{proc.stderr.strip() or '<no stderr>'}"
        )
    return [ROOT / line for line in proc.stdout.splitlines() if line]


def census(paths: list[Path]) -> dict[str, str]:
    """site key -> `<path>:<line>`, for every narrow VLE read found."""
    found: dict[str, str] = {}
    for path in paths:
        rel = path.relative_to(ROOT).as_posix()
        enclosing = ""
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            m = FN.match(line)
            if m:
                enclosing = m.group(1)
            # A doc comment naming the reader is prose about it, not a read.
            stripped = line.lstrip()
            if stripped.startswith("//"):
                continue
            call = CALL.search(line)
            if not call:
                continue
            arg = ARG.search(line, call.end() - 1)
            field = arg.group(1) if arg else ""
            key = f"{rel}::{enclosing}::{field}"
            found.setdefault(key, f"{rel}:{lineno}")
    return found


def main() -> int:
    try:
        paths = tracked_rust()
    except RuntimeError as e:
        print(f"  narrow-vle FAIL: {e}", file=sys.stderr)
        return 1
    if not paths:
        # A census that measured nothing must never read as a census that
        # found nothing.
        print("  narrow-vle FAIL: no tracked Rust under " + ", ".join(TREES), file=sys.stderr)
        return 1

    found = census(paths)
    failed = False

    for key in sorted(found.keys() - ADJUDICATED.keys()):
        failed = True
        print(
            f"  narrow-vle FAIL: {found[key]} reads a zint into a narrow type "
            f"and nothing says whether upstream refuses or truncates there.\n"
            f"    Read the field's upstream codec: `Zenoh080Bounded<uN>` means "
            f"the narrow read is right, plain `Zenoh080` means it truncates and "
            f"a narrow read stops a batch walk on a message the network "
            f"delivers. Then add `{key}` to ADJUDICATED in {Path(__file__).name}."
        )

    for key in sorted(ADJUDICATED.keys() - found.keys()):
        failed = True
        print(
            f"  narrow-vle FAIL: ADJUDICATED names `{key}`, which no longer "
            f"exists. An adjudication that outlives its code is the shape "
            f"open-debt item 47 is about — delete the row in the commit that "
            f"removed the read."
        )

    if failed:
        return 1

    mismatches = sorted(k for k, (v, _) in ADJUDICATED.items() if v == "MISMATCH")
    print(
        f"  narrow-vle: {len(found)} narrow zint read(s), every one adjudicated "
        f"against its upstream codec ({len(mismatches)} carried as MISMATCH)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
