#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y540 (§5.27) — api-compat-c: check ONE cdylib arm against upstream's own size table.

R311y540. Layer C1cc's footprint leg compares wz against the INSTALLED
`zenoh_opaque.h`, which exists for exactly one feature arm — whichever build the
machine provisioned. wz ships TWO arms (`Z_FEATURE_UNSTABLE_API` on and off), so
that leg structurally cannot see the other one, and the other one is where the
40-byte `z_owned_bytes_t` sat unchallenged from R311y498 to R311y540: a size no
zenoh-c 1.5.0 build has, on the arm nothing measured.

This closes that by asking upstream for the sizes instead of for a header.
zenoh-c generates `zenoh_opaque.h` from `build-resources/opaque-types`, a crate
whose whole purpose is to FAIL compilation with `type: X, align: N, size: M` per
type. Building it with a chosen feature set therefore yields the size table for
a build nobody has to install.

Both halves are read out of artifacts, never transcribed:

  - the sizes, from the generator's own stderr;
  - wz's names AND values, from the cdylib's `wz_capi_c_layout_name` /
    `wz_capi_c_layout` exports. Duplicating the name list here would have put
    back the drift hazard the array-shaped export was introduced to remove,
    one language over.

Only names that appear in BOTH are compared. wz's table also carries transparent
option structs (`z_get_options_t` and friends) and synthetic entries (`align`,
`z_id_t/align`), which upstream's opaque generator does not describe — those are
covered by the C-compiler probe in the footprint leg and are reported here as
skipped rather than silently ignored.
"""

from __future__ import annotations

import argparse
import ctypes
import pathlib
import re
import sys

SIZE_RECORD = re.compile(r"type: (\w+), align: (\d+), size: (\d+)")


def upstream_sizes(stderr_path: pathlib.Path) -> dict[str, tuple[int, int]]:
    """`{type_name: (size, align)}` from a generator run's stderr."""
    text = stderr_path.read_text(errors="replace")
    return {
        m.group(1): (int(m.group(3)), int(m.group(2)))
        for m in SIZE_RECORD.finditer(text)
    }


def wz_layout(cdylib: pathlib.Path) -> list[tuple[str, int]]:
    """`[(name, value)]` read out of the cdylib's own exports."""
    lib = ctypes.CDLL(str(cdylib))
    lib.wz_capi_c_layout.restype = ctypes.c_size_t
    lib.wz_capi_c_layout.argtypes = [ctypes.POINTER(ctypes.c_size_t), ctypes.c_size_t]
    lib.wz_capi_c_layout_name.restype = ctypes.c_char_p
    lib.wz_capi_c_layout_name.argtypes = [ctypes.c_size_t]

    total = lib.wz_capi_c_layout(None, 0)
    buf = (ctypes.c_size_t * total)()
    written = lib.wz_capi_c_layout(buf, total)
    if written != total:
        raise SystemExit(
            f"the cdylib reported {total} entries and then wrote {written}; "
            "its layout export is inconsistent with itself"
        )
    out = []
    for i in range(total):
        name = lib.wz_capi_c_layout_name(i)
        if name is None:
            raise SystemExit(f"the cdylib has no name for layout entry {i}")
        out.append((name.decode(), buf[i]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--generator-stderr", required=True, type=pathlib.Path)
    ap.add_argument("--cdylib", required=True, type=pathlib.Path)
    ap.add_argument("--arm", required=True, help="label for the diagnostics")
    args = ap.parse_args()

    if not args.generator_stderr.is_file():
        print(f"capi-c opaque arms [{args.arm}]: SKIP (no generator output at "
              f"{args.generator_stderr})")
        return 0
    if not args.cdylib.is_file():
        print(f"capi-c opaque arms [{args.arm}]: SKIP (no cdylib at {args.cdylib})")
        return 0

    upstream = upstream_sizes(args.generator_stderr)
    if not upstream:
        print(f"capi-c opaque arms [{args.arm}]: FAIL — the generator output "
              f"contains NO size records. A run that produced none did not "
              f"measure anything, and treating it as agreement would be a "
              f"vacuous pass.", file=sys.stderr)
        return 1

    mine = wz_layout(args.cdylib)
    compared, skipped, bad = 0, [], []
    for name, value in mine:
        if name not in upstream:
            skipped.append(name)
            continue
        compared += 1
        if upstream[name][0] != value:
            bad.append((name, value, upstream[name][0]))

    print(f"capi-c opaque arms [{args.arm}]: {compared} type(s) compared against "
          f"upstream's own generator, {len(skipped)} not described by it "
          f"(transparent structs and synthetic entries, covered by the C probe)")
    if not compared:
        print(f"capi-c opaque arms [{args.arm}]: FAIL — NOTHING was compared. "
              f"Every wz layout name was absent from the generator table, which "
              f"means the two are not talking about the same types.",
              file=sys.stderr)
        return 1
    for name, got, want in bad:
        print(f"  MISMATCH {name}: wz says {got}, upstream's generator says {want}",
              file=sys.stderr)
    if bad:
        print(f"capi-c opaque arms [{args.arm}]: FAIL — {len(bad)} type(s) "
              f"disagree. A drop-in whose types are a different SIZE is not a "
              f"drop-in; the C side stack-allocates these.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
