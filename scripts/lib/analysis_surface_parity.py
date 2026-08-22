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
5. R311y912 (unregistered item 409) — every ALL-CAPS SELF-REPORT SECTION in
   `USAGE` is named in `SELF_REPORT`, and every declared section is still
   there.

(3), (4) and (5) are the half that matters. A new capability added to ONE
surface now has to be written down here, and writing it down is where somebody
has to answer "and the other surface?" -- in prose, at the row, where the next
reader finds it.

(5) exists because a capability the command line delivers as a SECTION rather
than as a flag was in NEITHER of the two populations above. `LINK TYPES READ`
and `EXT BODIES READ` each answer a question a linking consumer asks, and
widening either moved none of this banner's numbers. That is a different miss
from an asymmetric row: a row the gate can see has been DECIDED, and a section
it cannot see has not been asked about. Both sections carry an `OPEN DEBT` tag
today, so the banner reports two where it used to report none -- which is the
whole of what the axis was added for.

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
    # R311y869 — the INTEREST plane, on BOTH surfaces from the round it landed,
    # which is the point of this table existing before the capability did. It is
    # a census plane, so the ABI reaches it through the same door the other four
    # use; the CLI needs its own flag because `--census` is the RECORD planes and
    # this one folds the control plane (the same split `--nodes` carries).
    "interest plane": ("--interests", "wz_dissect_pcap_census"),
    "payload plane": ("--payloads", "wz_dissect_pcap_census"),
    "all planes at once": ("--census", "wz_dissect_pcap_census"),
    "selector over the planes": ("--select", "wz_dissect_pcap_census_where"),
    "flow listing": ("--flows", "wz_dissect_pcap_summary"),
    "a machine-readable document": ("--json", "wz_dissect_pcap_census"),
    # R311y855 — moved here from ONLY_CLI. The ABI now walks the messages
    # itself, which is the only shape that could work: a stream message's bytes
    # live in the reassembled per-direction stream, so no caller holding the
    # capture file can slice one out.
    "field spans over a capture": ("--fields", "wz_dissect_pcap_fields"),
    "message listing": ("--messages", "wz_dissect_pcap_fields"),
    "bound on messages listed": ("--max-messages", "wz_dissect_pcap_fields"),
    # R311y856 — moved here from ONLY_CLI, where the reason was an OPEN DEBT.
    # The built-in decoders and the declaration dialect lived in `wz-analyze`,
    # which the cdylib must not depend on (it carries `wz-tls-record`, and
    # through it `ring`), so the seam this table named as public had nothing on
    # the ABI side able to build one. Both moved beside the map.
    "payload format decoding": ("--payload-format", "wz_dissect_pcap_fields_with_payloads"),
    "naming a decoded payload field": (
        "--payload-name",
        "wz_dissect_pcap_fields_with_payloads",
    ),
    # R311y857 — moved here from ONLY_CAPI, where it was the last OPEN DEBT.
    #
    # The reason there was OVERSTATED and this is where the correction lives:
    # it said the command line "has no flag for these (capture drops,
    # retransmits, sequence gaps, checksums, framing desyncs)", and measured by
    # running it, the report's `capture` object had carried all of those
    # unconditionally. What this surface genuinely could not reach was exactly
    # two things -- the fragment CHAIN statistics, and the checksums that
    # VERIFIED or were ABSENT (a failure count with no denominator). `--health`
    # reaches both and renders `wz-capture`'s own grouping, byte for byte the
    # document the ABI embeds.
    "loss and health counters": ("--health", "wz_dissect_pcap_summary"),
    # R311y884 (open-debt item 234) — reading a capture under the LIVE-TAP
    # ceilings. The ABI had this from R311y748 and the command line did not, so
    # `dropped_by_limits` -- the group that says what the ceilings cost -- was
    # zero on BOTH surfaces for a structural reason: neither built a bounded
    # dissection, so no cap existed to bite, and a structural zero reads exactly
    # like a measured one.
    #
    # R311y885 — THE RESIDUE THIS ROW USED TO CARRY WAS FALSE, and the
    # correction lives here because the row is where the next reader looks.
    #
    # It said: "the ABI's bounded door emits the SUMMARY document, and the drop
    # counters live in the HEALTH group, which only `wz_dissect_pcap_summary`
    # (unbounded) renders ... a linking consumer can bound the read and still
    # cannot see what the bound cost." Both doors call one `summary_json`, which
    # embeds the health group, so the bounded door had been reporting its own
    # drops since the round it landed. Measured, not re-read:
    # `the_bounded_door_reports_a_bound_that_bit` now pins the WHOLE group off
    # that door and reads `"flows":1`.
    #
    # The gap the false residue was pointing at is real and is one document
    # over: the CENSUS was unbounded and silent. That is the row below.
    "reading under the live-tap bounds": ("--bounded", "wz_dissect_pcap_summary_bounded"),
    # R311y885 — the ANALYSIS planes under those same ceilings, which is a
    # SECOND capability and not the row above restated. The row above is the
    # TRANSPORT document; this is the one a live tap actually reads, and until
    # this round it was the half that could not be capped: `wz_dissect_pcap_census`
    # reads with every limit `None`, on a link that does not end.
    #
    # The flag is the same `--bounded` on purpose. The command line bounds the
    # DISSECTION once and every document folds over it, so one flag reaches both
    # rows; the ABI takes bytes per call and therefore needs a door per document.
    # That asymmetry is a property of the two surfaces rather than a gap in
    # either, and it is written here so the next reader does not read the
    # repeated flag as a copy-paste.
    "bounded read of the analysis planes": ("--bounded", "wz_dissect_pcap_census_bounded"),
    # R311y887 — a NARROWED census under a ceiling. On the command line it is
    # `--select` and `--bounded` in the same argv, which needed nothing new;
    # on the ABI it needed a door, and the door takes the preset as an ARGUMENT
    # rather than being a fourth twin. `--select` is the flag named here because
    # it is the half that was missing from the ABI's bounded reach, and the
    # `--bounded` rows above already carry the other half.
    "a narrowed census under a ceiling": ("--select", "wz_dissect_pcap_census_where_limited"),
    # R311y917 (unregistered item 366) — the FIELD LAYER under a ceiling, which
    # is the plane that walks every message in the capture and was the last one
    # the ABI could only read unbounded. On the command line it is `--fields`
    # and `--bounded` in the same argv and always was, by the one-dissection
    # asymmetry the note above states; on the ABI it needed a door, and that
    # door takes the preset as an ARGUMENT rather than becoming a third and
    # fourth field twin. `--fields` is the flag named here for the reason the
    # census row names `--select`: it is the half that was missing from the
    # ABI's bounded reach.
    "the field layer under a ceiling": ("--fields", "wz_dissect_pcap_fields_limited"),
}

# Reachable ONLY from the command line, each with the reason it is not on the
# ABI. A reason that reads as "not done yet" is an open debt, and saying so is
# this table's job.
ONLY_CLI = {
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
    "reading from a live tap": (
        "--interface",
        "DELIBERATE and it is the ABI's own design, not an omission. Every "
        "wz_dissect_* entry point takes capture BYTES the CALLER holds, which "
        "is what makes a C consumer able to feed a tap it opened itself -- "
        "`DissectionLimits::for_live_tap` exists there for exactly that. "
        "Widening the ABI to open sockets would move a privilege across an FFI "
        "boundary to buy a caller something it can already do. Round 1999 "
        "(item 470).",
    ),
    "a census plane as CSV rows": (
        "--csv",
        "DELIBERATE, and the reason is what CSV IS. Every wz_dissect_* entry "
        "point hands back a JSON document a caller parses; CSV is a rendering "
        "for a tool that reads tables, and a C consumer holding the census "
        "document already has the rows -- it would be asking this library to "
        "format for it. The EMIT is shared, not the flag: "
        "`wz_capture::census_csv` reads the same typed tables `census_json` "
        "does, so an ABI symbol is one call away if a consumer ever wants the "
        "bytes rather than the fields. Round 2001 (item 473).",
    ),
    "bounding a live read": (
        "--for",
        "Rides the row above; a bound is meaningless without a tap to bound, "
        "and the parser refuses it alone for that reason. A C consumer driving "
        "its own tap owns its own stop rule.",
    ),
}

# Reachable ONLY from the C ABI.
ONLY_CAPI = {
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
    "diagnosing a declaration text without a capture": (
        "wz_dissect_declarations_diagnose",
        "DELIBERATE, on exactly the argument the row above makes, arriving for the "
        "second text a person types. The command line refuses a bad declaration at "
        "parse time and names the flag, which is the same answer delivered by "
        "running; a UI needs it before there is anything to run.",
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


# R311y912 (unregistered item 409) — the THIRD axis: a capability the command
# line delivers as a SELF-REPORT SECTION rather than as a flag.
#
# `USAGE` carries two of them, and both answer a question a consumer of either
# surface asks: which pcap link types this build decodes, and which extension
# BODIES it opens rather than showing as `value`. Neither is a flag and neither
# is a symbol, so the two checks above were blind to both — MEASURED when the
# `EXT BODIES READ` section was last widened, the banner's four numbers did not
# move by one.
#
# That is a different miss from an asymmetric ROW (item 242's "one-sided is a
# decision"): a row the gate can see has been decided, and a section it cannot
# see has not even been asked about. So the axis exists to force the same
# question the flag axis forces, and the answer for both sections today is that
# the ABI has no counterpart.
STRUCTURAL_HEADINGS = {"USAGE:", "OPTIONS:"}

SELF_REPORT = {
    # R311y913 (unregistered item 435) — both rows had `None` and an OPEN DEBT
    # tag for exactly one round, which is what an axis added to make a gap
    # countable is FOR. The door answers both questions in one document because
    # they are one question a consumer asks -- "what can you read?" -- and
    # because both lists are DERIVED (`readable_link_types_line`,
    # `readable_ext_bodies_line`), so the door, the help text and the dispatch
    # are one fact rather than three copies.
    "LINK TYPES READ:": (
        "wz_dissect_readable_surfaces",
        "An unread capture reports `messages decoded: 0`, and so does a capture "
        "with no zenoh traffic, so a consumer that cannot ask which link types "
        "this build decodes cannot tell its operator to re-capture.",
    ),
    "EXT BODIES READ:": (
        "wz_dissect_readable_surfaces",
        "An extension body this build does not open is COUNTED and NAMED and "
        "rendered as `value`, which reads exactly like `there was no structure "
        "here`. Both surfaces now answer which ones it opens, from the same "
        "dispatch-driven renderer.",
    ),
}


def cli_self_report_headings() -> set[str]:
    """Every ALL-CAPS section heading `USAGE` carries.

    Read from the same constant the flags come from, and deliberately by SHAPE
    rather than from a list of known headings: a third section added later must
    be decided here, which is the property the flag axis already has and this
    one was missing.
    """
    src = CLI.read_text()
    block = re.search(r'pub const USAGE: &str = "\\\n(.*?)\n";', src, re.S)
    if block is None:
        return set()
    return set(re.findall(r"^([A-Z][A-Z /]*:)$", block.group(1), re.M))


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
    # R311y913 — a self-report row's symbol is a NAMED symbol like any other.
    # Measured by leaving it out for one run: the symbol axis then reported
    # `wz_dissect_readable_surfaces` as unnamed while the section axis reported
    # it as answered, which is two halves of one table disagreeing.
    named_symbols |= {s for s, _ in SELF_REPORT.values() if s}

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

    # R311y912 — the self-report axis, in both directions like the two above.
    headings = cli_self_report_headings()
    if not headings:
        findings.append(
            "no section heading was read out of USAGE at all, so this axis "
            "would be green over an empty set"
        )
    for heading in sorted(set(SELF_REPORT) - headings):
        findings.append(
            f"this table declares the self-report section `{heading}` and "
            f"wz-analyze's USAGE no longer has it -- the row is stale"
        )
    for heading in sorted(headings - set(SELF_REPORT) - STRUCTURAL_HEADINGS):
        findings.append(
            f"wz-analyze's USAGE carries the self-report section `{heading}` and "
            f"this table does not name it. Add it to SELF_REPORT with the ABI "
            f"symbol that answers the same question, or with the reason there "
            f"is none -- a section is a capability a consumer reads, and until "
            f"this axis existed neither of the two here was ever asked about"
        )
    for symbol, _ in SELF_REPORT.values():
        if symbol and symbol not in symbols:
            findings.append(
                f"SELF_REPORT names C symbol `{symbol}` and wz-capi-dissect does "
                f"not export it -- the row is stale"
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

    # R311y855 — the TAG is the head of the reason, and a reason that argues an
    # item is open without leading with the tag is a FAILURE rather than a
    # silent zero.
    #
    # Measured, in this gate's own second round: R311y854's health-counter row
    # said "... and it is an OPEN DEBT on the CLI side", which reads correctly
    # and counted as nothing, so the banner reported one open item where there
    # were two. A count that under-reports debt is worse than no count -- it is
    # the confident zero this workspace keeps paying for -- and the fix cannot
    # be "remember to put it first", which is what had just failed.
    # The self-report rows answer to the SAME tag rule, and they must: an axis
    # added to make debt visible that then under-counted it would be the exact
    # failure the rule below was written for, one axis over.
    one_sided = (
        list(ONLY_CLI.values()) + list(ONLY_CAPI.values()) + list(SELF_REPORT.values())
    )
    mis_tagged = [
        reason
        for _, reason in one_sided
        if "OPEN DEBT" in reason and not reason.startswith("OPEN DEBT")
    ]
    if mis_tagged:
        print("analysis-surface-parity: FAIL", file=sys.stderr)
        for reason in mis_tagged:
            print(
                f"  - a reason calls an item an OPEN DEBT without leading with "
                f"the tag, so it counts as nothing: {reason[:80]}...",
                file=sys.stderr,
            )
        return 1
    open_debt = sum(1 for _, reason in one_sided if reason.startswith("OPEN DEBT"))
    print(
        f"  analysis-surface-parity: {len(BOTH)} capability(ies) on both surfaces, "
        f"{len(ONLY_CLI)} CLI-only, {len(ONLY_CAPI)} ABI-only, "
        f"{len(SELF_REPORT)} self-report section(s), {open_debt} of those "
        f"an OPEN DEBT; {len(flags)} flag(s), {len(symbols)} symbol(s) and "
        f"{len(headings)} section(s) accounted for"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
