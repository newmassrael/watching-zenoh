#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
EXPECTED_VERSION = 14

# R2108 (open-debt item 525) -- THE RECORD'S LAYOUT, pinned HERE and read from
# the artifact through `wz_dissect_record_layout`.
#
# `size, align, offset(ts_ns), offset(flow_id), offset(list_id),
# offset(anchor), offset(unit_len), offset(batch_index), offset(unit_offset),
# offset(direction), offset(anchor_space), offset(origin), offset(kind),
# offset(flags)`.
#
# ## Why the layout is pinned in this file and not only in the two tests
#
# It WAS pinned twice already: a Rust `size_of`/`offset_of` test and a C
# `sizeof`/`offsetof` block. Both live in the crate, and both are edited by the
# same commit that changes the struct -- so a round could widen the record,
# update both, and leave the ABI revision where it stood, with the whole tree
# agreeing with itself. That is not a hypothetical: the change item 525
# reverted did exactly that, and what caught it was a person reading the
# header, which is the detector this workspace has learned not to rely on.
#
# Two pins that move together are one pin. This third one is different in the
# only way that matters -- it sits three lines from EXPECTED_VERSION, so the
# layout and the revision are edited in one place or the gate reds.
EXPECTED_LAYOUT = (56, 8, 0, 8, 16, 24, 32, 40, 44, 48, 49, 50, 51, 52)
EXPECTED_SYMBOLS = {
    "wz_dissect_abi_version",
    # R2102 (open-debt item 524) — THE LIVE DOOR. Five symbols, and the first
    # entry here whose revision bump is not only about symbols: the memory rule
    # itself moved, because a live tap is a dissection kept alive between
    # packets and the header had promised that "no handle outlives the call
    # that made it".
    #
    # That is exactly the case the module doc above says must still be recorded
    # here -- "legitimate for a MEMORY-RULE change and must still be a
    # deliberate edit" -- and this round is both halves at once, which no
    # previous one has been. The callback half of the rule did NOT move: the
    # drain writes into a buffer the caller owns, which is what let this be a
    # widening rather than the callback registration that was refused before.
    "wz_dissect_live_open",
    "wz_dissect_live_push",
    "wz_dissect_live_drain",
    "wz_dissect_live_lost",
    "wz_dissect_live_close",
    # R2205 (open-debt item 560) — the BYTES a drained record was decoded from.
    # The memory rule did NOT move with it, and that is the fact worth pinning
    # here rather than assuming: this is the first door handing back something
    # that is neither a `char*` nor a fixed-layout record, so it is the one a
    # reader of this file would expect to have moved it. Bytes into a buffer the
    # CALLER sized add nothing to release and run no callback, so the revision
    # moves for the symbol alone.
    "wz_dissect_live_message_bytes",
    # R2171 (open-debt item 547) — the door BETWEEN the two families above and
    # the nine document doors below. It hands back the same opaque handle
    # `wz_dissect_live_open` does, so the memory rule does not move with it:
    # what moves is the symbol set, which is this pin's own subject.
    "wz_dissect_pcap_replay",
    # R2108 (open-debt item 525) — the layout door. Exported so THIS gate can
    # read the record's shape out of the artifact; it is not a door a consumer
    # has any use for, since a program that includes the header already has the
    # layout from its own compiler.
    "wz_dissect_record_layout",
    # R311y913 (unregistered item 435) — what this build can READ, with no
    # capture. The command line had answered it in `--help` for a while and the
    # linked surface could not answer it at all; R311y912 gave
    # `analysis_surface_parity.py` the axis that made the gap countable, and
    # this symbol is what that axis had counted as missing. The strings are
    # DERIVED from the link-type match and the two body dispatches, so this
    # door, the help text and the dispatch are one fact.
    "wz_dissect_readable_surfaces",
    # R311y855 — the FIELD layer, which is the walk this header had described
    # since R311y586 and could not perform.
    "wz_dissect_pcap_fields",
    # R311y856 — the payload seam. The decoders lived in the command line, so
    # the surface a product LINKS could not decode a payload at all; the
    # diagnostic beside it answers "is this declaration text valid, and if not
    # which line" with no capture, which is the question a UI asks while it is
    # being typed.
    "wz_dissect_pcap_fields_with_payloads",
    # R311y917 (unregistered item 366) — the field layer under a CEILING. The
    # one read plane with no bounded form, and the one that walks every message
    # in the capture; `max_messages_shown_per_flow` trims the output after the whole
    # dissection is already built, so it was never the bound it looks like. One
    # symbol on R311y887's pattern rather than a `_bounded` twin for each of the
    # two existing field doors, which would have made four.
    "wz_dissect_pcap_fields_limited",
    "wz_dissect_declarations_diagnose",
    # R311y851 — the four analysis planes' door. Both halves moved together,
    # which is the whole of what this gate asks.
    "wz_dissect_pcap_census",
    # R311y885 — the census under the live-tap ceilings. The bounded SUMMARY
    # had existed since R311y748 while the analysis planes stayed unbounded,
    # so the document a live tap needs was the one that could not be capped.
    "wz_dissect_pcap_census_bounded",
    # R311y854 — the selector: one door that narrows the census, one that
    # diagnoses the expression without a capture.
    "wz_dissect_pcap_census_where",
    # R311y887 — the census with the selector AND the limit preset as
    # arguments, which is the shape that stops a `_bounded` twin per document.
    # The three census doors above are kept, not replaced: a published symbol is
    # one a consumer links.
    "wz_dissect_pcap_census_where_limited",
    "wz_dissect_pcap_summary",
    "wz_dissect_pcap_summary_bounded",
    "wz_dissect_selector_diagnose",
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


def layout(cdylib: pathlib.Path) -> tuple[int, ...]:
    """The record layout the BUILT library reports, sized first then read.

    Two calls on purpose: the door answers its own length when handed a null,
    so the reader never has to hold a copy of the count -- which would be a
    fourth place the layout is written down, and the point of this arm is that
    there are already too many.
    """
    lib = ctypes.CDLL(str(cdylib))
    lib.wz_dissect_record_layout.restype = ctypes.c_size_t
    lib.wz_dissect_record_layout.argtypes = [
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_size_t,
    ]
    count = int(lib.wz_dissect_record_layout(None, 0))
    if count == 0:
        return ()
    buf = (ctypes.c_size_t * count)()
    written = int(lib.wz_dissect_record_layout(buf, count))
    if written != count:
        return ()
    return tuple(int(v) for v in buf)


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
    shape = layout(CDYLIB)
    if not shape:
        print(
            "capi-abi-pin: FAIL -- `wz_dissect_record_layout` reported no "
            "layout. An empty answer here reads exactly like agreement, so it "
            "cannot pass.",
            file=sys.stderr,
        )
        return 1
    added = sorted(symbols - EXPECTED_SYMBOLS)
    removed = sorted(EXPECTED_SYMBOLS - symbols)
    moved = version != EXPECTED_VERSION
    reshaped = shape != EXPECTED_LAYOUT

    if added or removed or moved or reshaped:
        print("capi-abi-pin: FAIL", file=sys.stderr)
        if reshaped:
            print(
                f"  - record layout is {shape}, pinned at {EXPECTED_LAYOUT}\n"
                f"    (size, align, then every field offset in declaration "
                f"order)",
                file=sys.stderr,
            )
            if not moved:
                print(
                    "\n  THE LAYOUT MOVED AND THE REVISION DID NOT. A field "
                    "read by OFFSET cannot notice that; a consumer built "
                    f"against {EXPECTED_VERSION} would read the new bytes at "
                    "the old positions and get plausible garbage with no error "
                    "anywhere. This is the one arm the crate's own two pins "
                    "cannot raise, because the commit that moves the layout "
                    "moves them too.",
                    file=sys.stderr,
                )
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
        f"set unchanged; record is {shape[0]} byte(s) / align {shape[1]} with "
        f"{len(shape) - 2} field offset(s), read from the artifact and pinned "
        f"beside the revision"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
