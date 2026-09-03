#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2301 (no register item) — PIN `wz-capi-c`'s WZ-OWN SYMBOL SET TO ITS
REVISION NUMBER, with the set read from the BUILT LIBRARY.

Answers item 634 of the unregistered register, which lives OUTSIDE this
repository -- the reason the citation above reads "no register item", the same
position `capi_c_config_surface.py` records for 548 and
`analysis_surface_config_free.py` for 564. The item is named in full here so a
reader grepping for it lands on this file.

## The item, and why R2300 created it

R2300 answered item 631 by shipping `wz_capi_c.h` and thirteen `wz_capi_c_*`
doors. Writing a header is what MADE this debt: from that moment "which build of
the library is this header for?" is a question a consumer can ask, and nothing
could answer it. `wz_dissect.h` has answered it since R311y748 --
`wz_dissect_abi_version` plus `capi_abi_pin.py` -- and `wz_capi_c.h` shipped
with neither. A door could be added and the only signal to a consumer was
whether their program still compiled.

The item forbids closing this by reusing the dissect revision, and it is right
to: the two libraries move independently, and one number covering both would
force a bump on every consumer of either whenever either moved. The MECHANISM is
shared; the numbers are not.

## What is derived and what is declared, because they are not the same thing

The item's own instruction is that the POPULATION be derived and never a
hand-written list. Both are honoured, and the distinction is what makes a pin
work at all:

  POPULATION (derived, three ways)  what symbols exist right now.
  BASELINE   (declared, one place)  what the current revision covers.

A pin with a derived baseline could not fail: the baseline would follow the
population wherever it went. So the baseline IS written down -- but it sits
three lines from `EXPECTED_REVISION`, which is the whole mechanism. Moving one
without the other is what reds, so a symbol added is a symbol whose revision
bump is unavoidable. `capi_abi_pin.py` records the same reasoning for the record
layout it pins: "two pins that move together are one pin".

## Three corners, and each sees something the others cannot

  ARTIFACT   `nm -D --defined-only` over the built cdylib. THE SSOT for what
             the library exports, and the reason the population is not read from
             Rust alone: a gate reading the source would pin the text its author
             had just edited, which is not evidence. It is also the only corner
             that can see a `#[no_mangle]` a CFG removed.

             ⚠ WHICH PROFILE, and what that costs. The lane hands this the DEBUG
             cdylib, so `lto` — `thin` in `[profile.release]` and off here —
             never runs over what this reads. A symbol that only LTO could drop
             would therefore pass. Measured at R2301 and it is zero today: the
             debug and release builds export the same 14 `wz_capi_c_*` symbols,
             and running this gate against the release artifact reports the same
             revision and set. Open-debt item 637 carries the widening; this
             paragraph exists so the claim above cannot be read as more than it
             is, which is the failure the sentence it replaced actually had.
  SOURCE     `capi_c_wz_door_header.exported`, IMPORTED rather than
             reimplemented. Two derivations of one population is the second copy
             this file exists to prevent, and the item names that gate's
             derivation specifically.
  REVISION   obtained by LOADING the cdylib and CALLING `wz_capi_c_abi_version`,
             so it is the number a consumer receives rather than a literal a
             regex found. The header's `WZ_CAPI_C_ABI_REVISION` is read too and
             must agree: that pair is what lets a consumer detect a library it
             was not compiled against, and a pair that disagreed at rest would
             make the check meaningless before anyone ran it.

## Absence is FAIL, never SKIP

The lane builds the cdylib immediately before calling here, so a missing
artifact is a lane defect and not a developer-box condition. A gate that cannot
read its input must not report green -- the shape open-debt item 413 records,
where an untracked-oracle lane skips quietly and prints pass.
"""

from __future__ import annotations

import ctypes
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import capi_c_wz_door_header as door_gate  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = ROOT / "crates" / "wz-capi-c" / "include" / "wz_capi_c.h"

# ── THE PIN. Both halves are edited together or this gate reds. ──────────
#
# Adding, removing or renaming a `wz_capi_c_*` door means editing BOTH lines
# below in the same commit. That is the enforcement: the revision cannot be
# forgotten, because the set it covers is written three lines from it.
#
# A revision bump with NO symbol change is legitimate -- the memory rule stated
# in `wz_capi_c.h` can change on its own -- and still has to be a deliberate
# edit here, because a revision that moves for a reason nobody wrote down is a
# revision nobody can reason about.
EXPECTED_REVISION = 1
EXPECTED_SYMBOLS = {
    # R2301 (item 634) — the revision door itself.
    "wz_capi_c_abi_version",
    # R311y540 — the drop-in's half of the layout gate.
    "wz_capi_c_layout",
    "wz_capi_c_layout_name",
    # R2172 (item 548) — which config keys wz's JSON5 reader honours.
    "wz_capi_c_config_honoured",
    "wz_capi_c_config_honoured_count",
    # R2300 (item 631) — emitting a stock-zenoh config and judging one.
    "wz_capi_c_config_to_json5",
    "wz_capi_c_config_validate",
    "wz_capi_c_config_validate_for_build",
    "wz_capi_c_config_validate_topology",
    "wz_capi_c_config_validate_topology_with_external",
    "wz_capi_c_config_link_scheme",
    "wz_capi_c_config_link_scheme_count",
    "wz_capi_c_config_zenoh_link_scheme",
    "wz_capi_c_config_zenoh_link_scheme_count",
}

PREFIX = "wz_capi_c_"


class Fatal(Exception):
    """A derivation that cannot be made. Never a silent pass."""


def artifact_symbols(cdylib: pathlib.Path) -> set[str]:
    """The `wz_capi_c_*` symbols the BUILT library defines, read from itself."""
    out = subprocess.run(
        ["nm", "-D", "--defined-only", str(cdylib)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {m.group(1) for m in re.finditer(rf"\b({PREFIX}[a-z_0-9]+)$", out, re.M)}


def artifact_revision(cdylib: pathlib.Path) -> int:
    """The revision a consumer receives: the loaded library, asked."""
    lib = ctypes.CDLL(str(cdylib))
    lib.wz_capi_c_abi_version.restype = ctypes.c_int32
    lib.wz_capi_c_abi_version.argtypes = []
    return int(lib.wz_capi_c_abi_version())


def header_revision(text: str) -> int:
    """`WZ_CAPI_C_ABI_REVISION` as the C preprocessor would see it.

    Read as a DEFINE rather than by finding the token anywhere, because this
    header explains the macro at length and names it while doing so.
    """
    m = re.search(r"^#define\s+WZ_CAPI_C_ABI_REVISION\s+(-?\d+)\s*$", text, re.M)
    if m is None:
        raise Fatal(
            f"{HEADER.relative_to(ROOT)} defines no WZ_CAPI_C_ABI_REVISION. A "
            "consumer cannot then tell what it compiled against, which is the "
            "whole of item 634."
        )
    return int(m.group(1))


def run(cdylib: pathlib.Path) -> int:
    if not cdylib.is_file():
        print(
            f"capi-c-abi-pin: FAIL -- {cdylib} is absent. The lane must build "
            "the cdylib before this gate runs; a symbol set read from nothing "
            "is not a symbol set.",
            file=sys.stderr,
        )
        return 1

    findings: list[str] = []

    built = artifact_symbols(cdylib)
    if not built:
        findings.append(
            f"the artifact defines no `{PREFIX}*` symbol at all. Either `nm` has "
            "stopped being read or the library stopped exporting wz's own "
            "doors; an empty population agrees with any pin."
        )

    # The SOURCE corner, from the gate that already derives it. Imported, never
    # reimplemented -- see the header.
    from_source = door_gate.exported(PREFIX)
    if not from_source:
        findings.append(
            "the source derivation returned no door, so its agreement with the "
            "artifact means nothing."
        )

    for name in sorted(built - from_source):
        findings.append(
            f"{name} is EXPORTED by the artifact and found in no tracked source. "
            "The source scanner has drifted from what actually ships."
        )
    for name in sorted(from_source - built):
        findings.append(
            f"{name} is declared `#[no_mangle]` in source and ABSENT from the "
            "artifact. A cfg removed it, so a consumer linking against this "
            "build cannot call it however the source reads."
        )

    for name in sorted(built - EXPECTED_SYMBOLS):
        findings.append(
            f"{name} is exported and NOT in the pin. Add it to EXPECTED_SYMBOLS "
            "and move EXPECTED_REVISION in the SAME edit -- a new door under the "
            "old revision is a library whose version cannot answer the only "
            "question a new door raises."
        )
    for name in sorted(EXPECTED_SYMBOLS - built):
        findings.append(
            f"{name} is in the pin and NOT exported. A removal is an ABI event "
            "too: drop it from EXPECTED_SYMBOLS and move EXPECTED_REVISION in "
            "the same edit."
        )

    got = artifact_revision(cdylib)
    if got != EXPECTED_REVISION:
        findings.append(
            f"the library reports revision {got} and the pin says "
            f"{EXPECTED_REVISION}. A revision may move on its own (the memory "
            "rule can change without a symbol changing), but it must move HERE "
            "too, or it moved for a reason nobody wrote down."
        )

    header_text = HEADER.read_text(errors="replace")
    said = header_revision(header_text)
    if said != got:
        findings.append(
            f"{HEADER.relative_to(ROOT)} says WZ_CAPI_C_ABI_REVISION is {said} "
            f"and the library answers {got}. The pair exists so a CONSUMER can "
            "detect a library it was not compiled against; disagreeing at rest "
            "makes that check meaningless before anyone runs it."
        )

    if findings:
        print("capi-c-abi-pin: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1

    print(
        f"capi-c-abi-pin: OK -- revision {got} covers {len(built)} `{PREFIX}*` "
        f"door(s), agreed by the artifact, the sources and the header"
    )
    return 0


def selftest() -> int:
    """Drive the readers against text and sets the real files cannot produce."""
    if header_revision("#define WZ_CAPI_C_ABI_REVISION 7\n") != 7:
        print("selftest: the define reader misread a revision", file=sys.stderr)
        return 1
    # A MENTION is not a definition: this header discusses the macro in prose
    # and in an example `if`, and either would be a false read.
    for text in [
        " * compare wz_capi_c_abi_version() against WZ_CAPI_C_ABI_REVISION\n",
        "if (v != WZ_CAPI_C_ABI_REVISION) { }\n",
    ]:
        try:
            header_revision(text)
        except Fatal:
            pass
        else:
            print(f"selftest: a mention was read as a define: {text!r}", file=sys.stderr)
            return 1

    # And the real header must still parse -- a gate aimed at a macro that moved
    # is the failure most likely to arrive silently.
    real = header_revision(HEADER.read_text(errors="replace"))
    if real != EXPECTED_REVISION:
        print(
            f"selftest: the header says {real}, the pin says {EXPECTED_REVISION}",
            file=sys.stderr,
        )
        return 1

    # The pin must not be empty, or every comparison above is vacuous.
    if not EXPECTED_SYMBOLS:
        print("selftest: the pin is empty and agrees with anything", file=sys.stderr)
        return 1

    print("capi-c-abi-pin: selftest OK")
    return 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--selftest"]
    try:
        if "--selftest" in sys.argv[1:]:
            sys.exit(selftest())
        if len(args) != 1:
            print(
                "usage: capi_c_abi_pin.py <libwz_capi_c.so> | --selftest",
                file=sys.stderr,
            )
            sys.exit(2)
        sys.exit(run(pathlib.Path(args[0])))
    except Fatal as e:
        print(f"capi-c-abi-pin: FAIL -- {e}", file=sys.stderr)
        sys.exit(1)
