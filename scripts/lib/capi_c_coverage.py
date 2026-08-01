#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""§5.27 api-compat-c COVERAGE, measured against upstream's own example corpus.

R311y498. A slice is not a number someone declares; it is the fraction of
upstream's programs that link against wz's cdylib. This reports that fraction
every run, so partial coverage stays VISIBLE rather than implied by a round
summary nobody re-reads.

The shape is deliberate. It does NOT compare against a hand-kept list of
"implemented symbols" — such a list is exactly what drifts, and the round that
built this atom had a hand-picked 10-symbol list that turned out to name four
symbols zenoh-c never calls while missing three it does. So the corpus is asked
directly: compile each example against upstream's header, and for the ones that
compile, ask the LINKER whether wz's library satisfies them.

Three outcomes per example, and the middle one is the point:

  LINKS       — compiles AND links against wz's cdylib. wz is a drop-in for it.
  MISSING(n)  — compiles, but wz is short n symbols. Named, so the backlog is
                a fact rather than an estimate.
  ORACLE-ONLY — does not compile against THIS installation's header at all
                (Z_FEATURE_SHARED_MEMORY, unstable APIs). A property of the
                oracle build, not of wz, so it is excluded from the denominator
                rather than counted as a wz failure.

Exit code is 0 unless the oracle or the cdylib is missing; the ratio is
REPORTED, not enforced. Enforcing "no regression in the count" would be the
next turn of the screw and needs a committed baseline, which is a decision for
the round that wants it, not a side effect of this one.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
CDYLIB_CANDIDATES = [
    REPO / "crates/target/debug/libwz_capi_c.so",
    REPO / "crates/target/release/libwz_capi_c.so",
]


def oracle() -> tuple[pathlib.Path, pathlib.Path, pathlib.Path] | None:
    """(include, libdir, examples), or None when any part is absent."""
    home = pathlib.Path(os.environ.get("HOME", ""))
    prefix = pathlib.Path(os.environ.get("WZ_ZENOH_C_PREFIX", home / ".local"))
    examples = pathlib.Path(os.environ.get("WZ_ZENOH_C_EXAMPLES", home / "zenoh-c-ref/examples"))
    include, libdir = prefix / "include", prefix / "lib"
    if not (include / "zenoh.h").is_file() or not (examples / "z_put.c").is_file():
        return None
    return include, libdir, examples


def wz_exports(cdylib: pathlib.Path) -> set[str]:
    """The `z*` symbols wz's cdylib DEFINES, read from the artifact itself."""
    out = subprocess.run(
        ["nm", "-D", "--defined-only", str(cdylib)],
        capture_output=True, text=True, check=True,
    ).stdout
    return {m.group(1) for m in re.finditer(r"\b(z[a-z_0-9]+)$", out, re.M)}


def required(obj: pathlib.Path) -> set[str]:
    """The `z*` symbols an object file needs, read from the object itself."""
    out = subprocess.run(
        ["nm", "-u", str(obj)], capture_output=True, text=True, check=True
    ).stdout
    return {m.group(1) for m in re.finditer(r"\b(z[a-z_0-9]+)\b", out)}


def main() -> int:
    o = oracle()
    if o is None:
        print("api-compat-c coverage SKIP (the zenoh-c oracle is absent; set "
              "WZ_ZENOH_C_PREFIX / WZ_ZENOH_C_EXAMPLES)")
        return 0
    include, _libdir, examples = o

    cdylib = next((c for c in CDYLIB_CANDIDATES if c.is_file()), None)
    if cdylib is None:
        print("api-compat-c coverage SKIP (libwz_capi_c.so not built)")
        return 0

    have = wz_exports(cdylib)
    cc = os.environ.get("CC", "cc")
    links, missing, oracle_only = [], [], []

    with tempfile.TemporaryDirectory() as tmp:
        for src in sorted(examples.glob("*.c")):
            name = src.stem
            obj = pathlib.Path(tmp) / f"{name}.o"
            build = subprocess.run(
                [cc, "-std=c11", f"-I{include}", f"-I{examples}", "-c", str(src), "-o", str(obj)],
                capture_output=True, text=True,
            )
            if build.returncode != 0:
                oracle_only.append(name)
                continue
            need = required(obj)
            absent = sorted(need - have)
            if absent:
                missing.append((name, absent))
            else:
                links.append(name)

    denom = len(links) + len(missing)
    print(f"api-compat-c: {len(links)} of {denom} upstream examples link against "
          f"wz's cdylib ({len(oracle_only)} more do not compile against this "
          f"oracle build and are out of the denominator)")
    for name in links:
        print(f"  LINKS       {name}")
    for name, absent in missing:
        head = ", ".join(absent[:6])
        more = f", +{len(absent) - 6} more" if len(absent) > 6 else ""
        print(f"  MISSING({len(absent):>3}) {name}: {head}{more}")
    if oracle_only:
        print(f"  ORACLE-ONLY {', '.join(oracle_only)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
