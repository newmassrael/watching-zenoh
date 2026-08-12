#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y748 (N55) — pin the dissect ABI's SYMBOL SET to its revision number.

## The contract this makes mechanical

`wz_dissect.h` states it in one sentence: the revision "moves when a SYMBOL or
the memory rule changes, never when the JSON gains fields". Nothing enforced
it. Adding a `#[no_mangle] pub extern "C" fn` and leaving the number alone
compiled, linked, passed every lane, and shipped a library whose version can no
longer answer the only question a new symbol raises -- does this build have it?

R311y748 nearly did exactly that: the round that added
`wz_dissect_pcap_summary_bounded` first wrote "the ABI version does not move"
into its own doc comment, on the strength of the RUST doc, which had narrowed
the committed contract to a symbol's SIGNATURE. Two statements of one rule had
drifted, and the drift was only caught by reading the header. That is the shape
this gate ends.

## Why both halves are read from the ARTIFACT

Neither half is parsed out of source text:

  * the SYMBOL SET comes from `nm -D --defined-only` over the release cdylib --
    the thing a consumer links against, so `#[no_mangle]` that LTO or a feature
    gate removed is absent here too;
  * the REVISION is obtained by LOADING that cdylib and CALLING
    `wz_dissect_abi_version()` through ctypes -- the number a consumer receives,
    not a literal a regex found near it.

A gate that read the Rust source would be pinning the same text the author just
edited, which is not evidence.

## The pin is a SET, and both directions fail

`EXPECTED` below is the pair. Any drift in either half reds and names what
moved. That deliberately includes a symbol REMOVAL and a version change with no
symbol change: the second is legitimate (the memory rule may change on its own)
and must still be a deliberate edit here, because a revision that moves for
reasons nobody wrote down is a revision nobody can reason about.
"""

from __future__ import annotations

import ctypes
import pathlib
import re
import subprocess
import sys

# The pinned pair. Edit BOTH halves deliberately -- see the module doc.
EXPECTED_VERSION = 2
EXPECTED_SYMBOLS = {
    "wz_dissect_abi_version",
    "wz_dissect_pcap_summary",
    "wz_dissect_pcap_summary_bounded",
    "wz_dissect_string_free",
    "wz_dissect_transport_message",
}

CDYLIB = pathlib.Path("crates/target/release/libwz_capi_dissect.so")


def exported(cdylib: pathlib.Path) -> set[str]:
    """The `wz_dissect_*` symbols the artifact DEFINES, read from itself."""
    out = subprocess.run(
        ["nm", "-D", "--defined-only", str(cdylib)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {m.group(1) for m in re.finditer(r"\b(wz_dissect_[a-z_0-9]+)$", out, re.M)}


def revision(cdylib: pathlib.Path) -> int:
    """The revision a consumer receives: the loaded library, asked."""
    lib = ctypes.CDLL(str(cdylib))
    lib.wz_dissect_abi_version.restype = ctypes.c_int
    lib.wz_dissect_abi_version.argtypes = []
    return int(lib.wz_dissect_abi_version())


def main() -> int:
    if not CDYLIB.is_file():
        # A gate that cannot read its input must not report green. The lane
        # builds this artifact immediately before calling here, so its absence
        # is a lane defect rather than a dev-box condition.
        print(
            f"capi-abi-pin: FAIL -- {CDYLIB} is absent. The lane must build the "
            f"release cdylib before this gate runs; a symbol set read from "
            f"nothing is not a symbol set.",
            file=sys.stderr,
        )
        return 1

    symbols = exported(CDYLIB)
    if not symbols:
        print(
            f"capi-abi-pin: FAIL -- {CDYLIB} exports ZERO `wz_dissect_*` "
            f"symbols. An empty population is indistinguishable from total "
            f"compliance, so it cannot pass.",
            file=sys.stderr,
        )
        return 1

    version = revision(CDYLIB)
    added = sorted(symbols - EXPECTED_SYMBOLS)
    removed = sorted(EXPECTED_SYMBOLS - symbols)
    moved = version != EXPECTED_VERSION

    if added or removed or moved:
        print("capi-abi-pin: FAIL", file=sys.stderr)
        for s in added:
            print(f"  - exported but not pinned: {s}", file=sys.stderr)
        for s in removed:
            print(f"  - pinned but not exported: {s}", file=sys.stderr)
        if moved:
            print(
                f"  - revision is {version}, pinned at {EXPECTED_VERSION}",
                file=sys.stderr,
            )
        if (added or removed) and not moved:
            print(
                "\n  THE SYMBOL SET MOVED AND THE REVISION DID NOT. "
                "`wz_dissect.h` says the revision moves when a SYMBOL or the "
                "memory rule changes; a consumer has no other way to ask "
                "whether this build carries the symbol.",
                file=sys.stderr,
            )
        elif moved and not (added or removed):
            print(
                "\n  THE REVISION MOVED AND THE SYMBOL SET DID NOT. That is "
                "legitimate for a MEMORY-RULE change and must still be recorded "
                "here, so the number never moves for a reason nobody wrote "
                "down.",
                file=sys.stderr,
            )
        print(
            f"\n  Update EXPECTED_VERSION / EXPECTED_SYMBOLS in "
            f"{pathlib.Path(__file__).name} in the same commit as the change.",
            file=sys.stderr,
        )
        return 1

    print(
        f"  capi-abi-pin: ABI {version}, {len(symbols)} exported symbol(s), "
        f"set unchanged"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
