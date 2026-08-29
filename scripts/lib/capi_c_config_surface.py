#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2172 (no register item) — the LINKED library says which config keys it honours.

Closes item 548 of the unregistered register, which lives outside this tree and
therefore has no `debt-` id to cite — the same position `debt_plane_census.py`
and `capi_c_config_surface`'s siblings record for themselves.

## The gap

`wz_dissect_readable_surfaces` set the precedent: a build reports WHAT IT CAN
READ, out of its own dispatch, so a consumer asks the artifact instead of
guessing. Configuration had no counterpart. A consumer — or a checker — wanting
to know which config keys THIS build honours had exactly one route left: parse
`crates/wz-runtime-tokio/src/zenoh_config.rs` and hope the constant is still
spelled the way it was.

That direction of failure is the one this repository keeps paying for. A parser
aimed at a moved module does not go RED, it matches nothing and reports an empty
set — the consumer-side face of "a population of zero reports green".

## Why the door is in `wz-capi-c` and not beside its precedent

Measured rather than assumed, and it is the opposite of where the register's own
prescription pointed:

  * `wz-capi-dissect` does not depend on `wz-runtime-tokio` and must not start:
    `analysis_surface_parity.py`'s `NO_REACH_PATH[2]` already DECLARES that
    neither analysis surface reads or writes configuration — "they take capture
    bytes and hand back documents" — so a config symbol there would contradict a
    live gate, not just widen a crate;
  * `wz-capi-c` already takes configuration (`z_config_*` / `zc_config_*`,
    seventeen doors) and already depends on `wz-runtime-tokio`;
  * and it already carries wz-OWN doors of exactly this shape —
    `wz_capi_c_layout` / `wz_capi_c_layout_name`, whose own doc gives this
    gate's argument verbatim: the alternative is "a second copy ... in the tool,
    which is the drift hazard the array form was introduced to remove".

## What this checks, and what it deliberately leaves to the Rust side

HERE (the artifact, through ctypes — no upstream oracle, so it runs anywhere):

  * both symbols are EXPORTED. Before this round they were not, and that is the
    red this gate was written against;
  * the count is NOT ZERO. A build reporting an empty surface would satisfy
    every "the symbol is there" assertion while telling a consumer nothing;
  * every index below the count yields a non-empty, NUL-terminated key, and the
    first index AT the count yields NULL, so the end of the list is a fact the
    caller can find rather than a length it has to trust.

NOT HERE, stated rather than hidden: whether that list EQUALS
`HONOURED_CONFIG_KEYS`. Reading the constant here would mean parsing Rust, which
is the second copy this door exists to remove — one language over, exactly as
`wz_capi_c_layout_name`'s doc warns. That equality is held in the crate, by
`the_config_surface_door_reports_the_constant_and_not_a_second_copy`, where the
constant is a value and not a regex.
"""

from __future__ import annotations

import argparse
import ctypes
import pathlib
import sys

COUNT = "wz_capi_c_config_honoured_count"
KEY = "wz_capi_c_config_honoured"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "cdylib",
        type=pathlib.Path,
        help="the built libwz_capi_c.so to interrogate",
    )
    args = ap.parse_args()

    if not args.cdylib.is_file():
        print(
            f"capi-c-config-surface: FAIL -- {args.cdylib} is not a file. This "
            f"gate reads the ARTIFACT; without one it has measured nothing and "
            f"must not report green.",
            file=sys.stderr,
        )
        return 1

    lib = ctypes.CDLL(str(args.cdylib))

    missing = [name for name in (COUNT, KEY) if not hasattr(lib, name)]
    if missing:
        print(
            f"capi-c-config-surface: FAIL -- {args.cdylib.name} does not export "
            f"{', '.join(missing)}. A consumer asking which config keys this "
            f"build honours is left parsing "
            f"`crates/wz-runtime-tokio/src/zenoh_config.rs`, and a parser aimed "
            f"at a moved module reports an EMPTY set rather than an error.",
            file=sys.stderr,
        )
        return 1

    count_fn = getattr(lib, COUNT)
    count_fn.restype = ctypes.c_size_t
    count_fn.argtypes = []
    key_fn = getattr(lib, KEY)
    key_fn.restype = ctypes.c_char_p
    key_fn.argtypes = [ctypes.c_size_t]

    count = count_fn()
    if count == 0:
        print(
            "capi-c-config-surface: FAIL -- the build reports ZERO honoured "
            "config keys. An empty surface satisfies every 'the symbol is "
            "exported' assertion and tells a consumer nothing, which is the "
            "shape this gate exists to refuse.",
            file=sys.stderr,
        )
        return 1

    problems: list[str] = []
    keys: list[str] = []
    for index in range(count):
        raw = key_fn(index)
        if raw is None:
            problems.append(
                f"index {index} is NULL below the reported count of {count} -- "
                f"the count and the table disagree."
            )
            continue
        key = raw.decode("utf-8", errors="replace")
        if not key.strip():
            problems.append(f"index {index} is an empty key.")
        keys.append(key)

    # The end has to be FINDABLE, not merely promised by the count: a consumer
    # walking until NULL is the shape `wz_capi_c_layout_name` already taught.
    if key_fn(count) is not None:
        problems.append(
            f"index {count} (one past the reported count) is not NULL, so a "
            f"consumer walking to the end reads past the table."
        )

    if problems:
        print(
            f"capi-c-config-surface: FAIL -- {len(problems)} problem(s) over "
            f"{count} reported key(s):",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(
        f"  capi-c-config-surface: {count} honoured config key(s) read from the "
        f"artifact, none empty, the end reachable; the list's EQUALITY with "
        f"HONOURED_CONFIG_KEYS is held in-crate, not by parsing Rust here"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
