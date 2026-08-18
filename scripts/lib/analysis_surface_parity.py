#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y854 (debt-analysis-surface-parity) — pin which SURFACE reaches each of
wz's analysis capabilities.

## The failure this ends

wz exports its dissection through two consumption surfaces:

  * `wz-analyze`, the command line -- a person at a terminal;
  * `wz-capi-dissect`, the C ABI -- what a framework LINKS.

They carried different halves of it for months, and the half a product links
was the thinner one: the keyexpr, node, query and payload planes were compiled
into every build of the cdylib (`wz-capture` is its own dependency) and had no
symbol until R311y851. Nothing measured that. The delta was discovered by
reading two files side by side, and it had been widening for as long as either
surface had been growing.

This is the same class as an atom compiled into a preset with no flag to reach
it -- the capability ships and the consumer cannot call it. That class HAS a
gate (`apfull_membership.py`), which is why it gets found in one round instead
of in six. This is that gate for the analysis surfaces, and it is deliberately
the same shape: a table nobody can leave un-updated, failing in BOTH
directions.

## What it checks

1. Every capability's declared CLI flag is still in `wz-analyze`'s `USAGE`.
2. Every capability's declared C symbol is still exported by
   `wz-capi-dissect`'s source.
3. Every flag in `USAGE` is named by some capability.
4. Every `wz_dissect_*` symbol is named by some capability.

(3) and (4) are the half that matters. A new capability added to ONE surface
now has to be written down here, and writing it down is where somebody has to
answer "and the other surface?" -- in prose, at the row, where the next reader
finds it.

## What it deliberately does NOT check

That both surfaces reach everything. They should not: a keylog is a file path a
person types and a bounded read is a memory statement a C caller makes, and
forcing symmetry would be a worse contract than the asymmetric one. `ONLY_CLI`
and `ONLY_CAPI` carry a REASON each, and the reason is the deliverable -- an
entry whose reason is "not done yet" is a debt this file makes visible rather
than one it hides.

The C surface is read from SOURCE and not from the cdylib, unlike
`capi_abi_pin.py`, which reads `nm` over the artifact. The two answer different
questions: that gate asks what a consumer can LINK, this one asks what the
project has DECIDED. Reading source here means this runs in Layer C0 with no
build, which is what makes it cheap enough to be run every time.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CLI = ROOT / "crates" / "wz-analyze" / "src" / "lib.rs"
CAPI = ROOT / "crates" / "wz-capi-dissect" / "src" / "lib.rs"

# capability -> (cli flag or None, capi symbol or None)
#
# BOTH surfaces reach these.
BOTH = {
    "keyexpr plane": ("--throughput", "wz_dissect_pcap_census"),
    "query plane": ("--exchanges", "wz_dissect_pcap_census"),
    "node plane": ("--nodes", "wz_dissect_pcap_census"),
    "payload plane": ("--payloads", "wz_dissect_pcap_census"),
    "all planes at once": ("--census", "wz_dissect_pcap_census"),
    "selector over the planes": ("--select", "wz_dissect_pcap_census_where"),
    "flow listing": ("--flows", "wz_dissect_pcap_summary"),
    "a machine-readable document": ("--json", "wz_dissect_pcap_census"),
}

# Reachable ONLY from the command line, each with the reason it is not on the
# ABI. A reason that reads as "not done yet" is an open debt, and saying so is
# this table's job.
ONLY_CLI = {
    "field spans over a capture": (
        "--fields",
        "OPEN DEBT (debt-analysis-surface-parity). `wz_dissect_transport_message` "
        "walks ONE message the caller already holds the bytes of, and no ABI call "
        "hands back a message's bytes or its coordinate -- a stream message lives "
        "in the reassembled per-direction stream, which only this library has. So "
        "the walk `wz_dissect.h` describes cannot be performed from C today.",
    ),
    "message listing": (
        "--messages",
        "OPEN DEBT, the same one: the summary reports per-flow COUNTS, so a "
        "consumer has nothing to enumerate messages by.",
    ),
    "bound on messages listed": (
        "--max-messages",
        "Follows the two rows above -- a bound on a listing the ABI does not have.",
    ),
    "payload format decoding": (
        "--payload-format",
        "OPEN DEBT (debt-analysis-surface-parity). `payload::formats::FormatMap` "
        "is public and nothing on the ABI takes one.",
    ),
    "naming a decoded payload field": (
        "--payload-name",
        "Rides the row above: a schemaless walk recovers a field NUMBER and never "
        "a name, so this is meaningless without the format rule that precedes it.",
    ),
    "TLS decryption from a key log": (
        "--keylog",
        "DELIBERATE. A key log is a file path a person supplies, and the ABI takes "
        "capture BYTES rather than paths -- keys carried inside the capture's own "
        "Decryption Secrets Blocks are already used by every door here. Widening "
        "the ABI to take key material is a decision about handling secrets across "
        "an FFI boundary, not an omission.",
    ),
    "declaring a UDP port to be QUIC": (
        "--quic",
        "DELIBERATE for now: a declaration is a human judgement about a capture "
        "that begins mid-connection, and the report says which flows were declared "
        "rather than recognised. A C consumer wanting it would want a whole "
        "declaration struct, which this ABI's design refuses (see its module doc).",
    ),
    "the short-header connection id length": (
        "--quic-cid-len",
        "Rides the row above; it is meaningless without a QUIC declaration.",
    ),
    "declaring a link type to be raw serial": (
        "--serial",
        "DELIBERATE, on the same argument as the QUIC declaration above.",
    ),
}

# Reachable ONLY from the C ABI.
ONLY_CAPI = {
    "loss and health counters": (
        "wz_dissect_pcap_summary",
        "The CLI has no flag for these (capture drops, retransmits, sequence gaps, "
        "checksums, framing desyncs). Measured across both surfaces in the SRS "
        "audit: this is the ONE direction where the ABI is the richer surface, and "
        "it is an OPEN DEBT on the CLI side rather than a decision.",
    ),
    "a bounded read": (
        "wz_dissect_pcap_summary_bounded",
        "DELIBERATE. A cap is a statement about the CALLER's memory, and the "
        "command line reads a file, which ends. `DissectionLimits::for_live_tap` "
        "exists for a tap, not for a terminal.",
    ),
    "one message's field tree": (
        "wz_dissect_transport_message",
        "The CLI walks messages it found itself (`--fields`); this takes bytes the "
        "CALLER holds. Two different questions rather than one missing flag.",
    ),
    "diagnosing a selector without a capture": (
        "wz_dissect_selector_diagnose",
        "DELIBERATE. It answers 'is this expression valid, and if not where' while "
        "it is being TYPED. A command line finds that out by running.",
    ),
    "the ABI revision": (
        "wz_dissect_abi_version",
        "Not an analysis capability -- it is how a consumer refuses a library whose "
        "memory rules moved. A command line has no such question.",
    ),
    "releasing a returned string": (
        "wz_dissect_string_free",
        "The memory contract. Not an analysis capability.",
    ),
}

# CLI flags that are not capabilities of the analysis surface at all.
NOT_A_CAPABILITY = {"-h, --help"}


def cli_flags() -> set[str]:
    """Every option `wz-analyze --help` prints, read from the USAGE constant."""
    src = CLI.read_text()
    block = re.search(r'pub const USAGE: &str = "\\\n(.*?)\n";', src, re.S)
    if block is None:
        print(
            "analysis-surface-parity: FAIL -- wz-analyze's USAGE constant was not "
            "found. A surface read from nothing is not a surface.",
            file=sys.stderr,
        )
        sys.exit(1)
    return set(re.findall(r"^ {4}(-[A-Za-z0-9-]+(?:, --[a-z0-9-]+)?)", block.group(1), re.M))


def capi_symbols() -> set[str]:
    """Every `wz_dissect_*` function the ABI declares, read from its source."""
    src = CAPI.read_text()
    return set(re.findall(r'pub (?:unsafe )?extern "C" fn (wz_dissect_[a-z_0-9]+)', src))


def main() -> int:
    flags = cli_flags()
    symbols = capi_symbols()
    if not flags or not symbols:
        print(
            f"analysis-surface-parity: FAIL -- read {len(flags)} flag(s) and "
            f"{len(symbols)} symbol(s). An empty population is indistinguishable "
            f"from total compliance, so it cannot pass.",
            file=sys.stderr,
        )
        return 1

    named_flags = {f for f, _ in BOTH.values() if f} | set(NOT_A_CAPABILITY)
    named_flags |= {f for f, _ in ONLY_CLI.values()}
    named_symbols = {s for _, s in BOTH.values() if s}
    named_symbols |= {s for s, _ in ONLY_CAPI.values()}

    findings: list[str] = []
    for flag in sorted(named_flags - flags):
        findings.append(
            f"the table names CLI flag `{flag}` and wz-analyze's USAGE does not "
            f"have it -- the row is stale"
        )
    for symbol in sorted(named_symbols - symbols):
        findings.append(
            f"the table names C symbol `{symbol}` and wz-capi-dissect does not "
            f"export it -- the row is stale"
        )
    for flag in sorted(flags - named_flags):
        findings.append(
            f"wz-analyze has `{flag}` and this table does not name it. Add it to "
            f"BOTH, to ONLY_CLI with the reason the ABI cannot reach it, or to "
            f"NOT_A_CAPABILITY -- the question 'and the other surface?' is what "
            f"this gate exists to force somebody to answer"
        )
    for symbol in sorted(symbols - named_symbols):
        findings.append(
            f"wz-capi-dissect exports `{symbol}` and this table does not name it. "
            f"Add it to BOTH or to ONLY_CAPI with its reason"
        )

    if findings:
        print("analysis-surface-parity: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        print(
            f"\n  Edit {pathlib.Path(__file__).name} in the same commit as the "
            f"change.",
            file=sys.stderr,
        )
        return 1

    open_debt = sum(
        1
        for _, reason in list(ONLY_CLI.values()) + [(s, r) for s, r in ONLY_CAPI.values()]
        if reason.startswith("OPEN DEBT")
    )
    print(
        f"  analysis-surface-parity: {len(BOTH)} capability(ies) on both surfaces, "
        f"{len(ONLY_CLI)} CLI-only, {len(ONLY_CAPI)} ABI-only, {open_debt} of those "
        f"an OPEN DEBT; {len(flags)} flag(s) and {len(symbols)} symbol(s) accounted for"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
