#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

r"""R2441 (no register item) — pin the replay ABI's SYMBOL SET, its revision,
and its record layout, all three read from the ARTIFACT.

The citation is `no register item` for `debt_plane_census.py`'s reason: the item
this gate answers for -- unregistered open-debt item 693 -- lives in the
agent-memory register outside this repository and has no `debt-` row in the
store. The round is `Round 2441` in the atomic ledger.

## Why this is a second copy of `capi_abi_pin.py`'s idea and not a call into it

That script is written against `wz-capi-dissect`: its symbol prefix, its
version function, its record's fourteen-value layout and its pinned set are all
literals in its own body, and its module doc argues at length that the pin
being a deliberate edit IN THAT FILE is the property that makes it work.
Parameterising it would turn two pins that must each be edited on purpose into
one mechanism with two configurations, and the first time a round widened both
sets it would edit one table. The shared thing here is a technique, not a value,
and this workspace's rule for that is the one `wz-packet-fixtures` states: only
the arithmetic is shared, never the claims.

## What is read, and from where

Nothing is parsed out of source text, because a gate that reads the file its
author just edited is pinning the edit rather than checking it:

  * the SYMBOL SET comes from `nm -D --defined-only` over the release cdylib —
    the thing a consumer links, so a `#[no_mangle]` that LTO removed is absent
    here too;
  * the REVISION comes from LOADING that cdylib and CALLING
    `wz_replay_abi_version()` through ctypes;
  * the LAYOUT comes from calling `wz_replay_emission_layout()` on the same
    loaded library, sized first and read second, so this file never holds a
    copy of the count.

## Both directions fail

`EXPECTED_*` below is the pin. Drift in any of the three reds and names what
moved. That deliberately includes a symbol REMOVAL and a revision that moves
with no symbol change: the second is legitimate — the memory rule may change on
its own — and must still be a deliberate edit here, because a revision that
moves for reasons nobody wrote down is a revision nobody can reason about.
"""

from __future__ import annotations

import ctypes
import pathlib
import re
import subprocess
import sys

# The pinned triple. Edit each half deliberately -- see the module doc.
EXPECTED_VERSION = 1

EXPECTED_SYMBOLS = {
    "wz_replay_abi_version",
    # The record layout, reported by the artifact so a binding in any language
    # can check its own `sizeof` against it.
    "wz_replay_emission_layout",
    # The cheap door: is this schedule playable at all.
    "wz_replay_schedule_check",
    # The plan half proper -- delays and their sources, and the whole-plan
    # refusal that still shows the plan.
    "wz_replay_plan_delays",
    # The mutation half, answered in the same door for both of its operands.
    "wz_replay_mutate",
}

# `size, align, offset(delay_millis), offset(source), offset(reserved)`.
#
# Pinned as a TUPLE rather than as five names, because the order is part of what
# the door promises: a consumer reads these positionally.
EXPECTED_LAYOUT = (16, 8, 0, 8, 12)

CDYLIB = pathlib.Path("crates/target/release/libwz_capi_replay.so")


def exported(cdylib: pathlib.Path) -> set[str]:
    """The `wz_replay_*` symbols the artifact DEFINES, read from itself."""
    out = subprocess.run(
        ["nm", "-D", "--defined-only", str(cdylib)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {m.group(1) for m in re.finditer(r"\b(wz_replay_[a-z_0-9]+)$", out, re.M)}


def revision(lib: ctypes.CDLL) -> int:
    """The revision a consumer receives: the loaded library, asked."""
    lib.wz_replay_abi_version.restype = ctypes.c_int
    lib.wz_replay_abi_version.argtypes = []
    return int(lib.wz_replay_abi_version())


def layout(lib: ctypes.CDLL) -> tuple[int, ...]:
    """The record layout the BUILT library reports, sized first then read.

    Two calls on purpose: the door answers its own length when handed a null,
    so this file never holds a copy of the count -- which would be one more
    place the layout is written down, and there being too many of those is the
    whole reason the door exists.
    """
    lib.wz_replay_emission_layout.restype = ctypes.c_size_t
    lib.wz_replay_emission_layout.argtypes = [
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_size_t,
    ]
    count = int(lib.wz_replay_emission_layout(None, 0))
    if count == 0:
        return ()
    buf = (ctypes.c_size_t * count)()
    if int(lib.wz_replay_emission_layout(buf, count)) != count:
        return ()
    return tuple(int(v) for v in buf)


def main() -> int:
    if not CDYLIB.is_file():
        # A gate that cannot read its input must not report green. The lane
        # builds this artifact immediately before calling here, so its absence
        # is a lane defect rather than a dev-box condition.
        print(
            f"capi-replay-abi-pin: FAIL -- {CDYLIB} is absent. The lane must "
            "build the release cdylib before this gate runs; a symbol set read "
            "from nothing is not a symbol set.",
            file=sys.stderr,
        )
        return 1

    symbols = exported(CDYLIB)
    if not symbols:
        print(
            f"capi-replay-abi-pin: FAIL -- {CDYLIB} exports ZERO `wz_replay_*` "
            "symbols. An empty population is indistinguishable from total "
            "compliance, so it cannot pass.",
            file=sys.stderr,
        )
        return 1

    lib = ctypes.CDLL(str(CDYLIB))
    version = revision(lib)
    reported = layout(lib)

    problems: list[str] = []
    for name in sorted(EXPECTED_SYMBOLS - symbols):
        problems.append(f"  - PIN NAMES `{name}` and the artifact does not export it")
    for name in sorted(symbols - EXPECTED_SYMBOLS):
        problems.append(
            f"  - artifact exports `{name}` and the pin does not name it. A new "
            "symbol is a new question a consumer can ask, which is exactly what "
            "the revision answers -- move both."
        )
    if version != EXPECTED_VERSION:
        problems.append(
            f"  - revision is {version}, pinned at {EXPECTED_VERSION}"
        )
    if reported != EXPECTED_LAYOUT:
        problems.append(
            f"  - wz_replay_emission layout is {reported}, pinned at "
            f"{EXPECTED_LAYOUT}. A consumer built against the pinned layout "
            "would read `source` out of the wrong bytes."
        )

    if problems:
        print("capi-replay-abi-pin: FAIL")
        print("\n".join(problems))
        print(
            "\n  Update EXPECTED_VERSION / EXPECTED_SYMBOLS / EXPECTED_LAYOUT "
            f"in {pathlib.Path(__file__).name}, deliberately and in the commit "
            "that moved them."
        )
        return 1

    print(
        f"capi-replay-abi-pin: OK -- revision {version}, {len(symbols)} symbol(s), "
        f"layout {reported}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
