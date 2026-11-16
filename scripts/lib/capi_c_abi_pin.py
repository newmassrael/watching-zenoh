#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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

             EVERY PROFILE THE LANE BUILDS, and the set must be the SAME in
             each. R2309 (open-debt item 637) widened this: until then the lane
             handed over the DEBUG cdylib alone, so `lto` — `thin` in
             `[profile.release]` and off in debug — never ran over what this
             read, and a symbol only LTO could drop would have passed. See
             "Profile invariance" below.
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

## Profile invariance (R2309, open-debt item 637)

The item's charge was that this pin "cannot structurally see a symbol LTO
removes", and the answer is NOT to swap debug for release -- that would only
move the blind spot to the other profile, since a symbol present in release
and missing from debug is an ABI event too. The answer is that the wz-own
door set is a claim about the LIBRARY, not about a build of it, so this gate
reads EVERY profile the lane produces and requires them to AGREE.

  * `REQUIRED_PROFILES` is DECLARED, not derived from what the caller passed.
    A required set read off the arguments would be satisfied by whatever
    arrived and could never fail -- the trap R2300 named for baselines. So
    handing this one profile is a FAIL that says which one is missing.
  * The comparison is symmetric and names the direction: a door in release
    and not in debug reads as clearly as the reverse, and neither is assumed
    to be the mistake.
  * The pin, the source scan and the header are then checked against EACH
    profile rather than against a union, so a finding always says which build
    it came from.

WHY THE DISSECT PIN NEXT DOOR STAYS RELEASE-ONLY, which item 637 also asked
to be said rather than left implicit. `capi_abi_pin.py` reads
`crates/target/release/libwz_capi_dissect.so` because its lane (C1bo) LINKS A
REAL C PROGRAM against that exact file -- `run-ci.sh` compiles the probe with
`-L crates/target/release -lwz_capi_dissect` -- so the artifact it pins is the
one a consumer receives, LTO and all. There is no blind spot to widen there.
C1ch links no C program: it reads the cdylib with `nm` and ctypes, which is
why the cheapest build was enough for it and why the profile question could
sit unasked.

WHAT THE WIDENING COSTS, measured rather than estimated. On the build machine
(31 cores), from an empty `CARGO_TARGET_DIR`: debug 17.88 s, release 24.99 s
-- release is 1.40x debug, not an order of magnitude, because this crate's
dependency graph dominates and `lto = "thin"` is thin. The hosted workflow
runs one job, and C1bo later builds `wz-capi-dissect --release` in it, so the
release profile is warmed here rather than paid for twice; the true increment
is below the 25 s figure.

## Absence is FAIL, never SKIP

The lane builds the cdylib immediately before calling here, so a missing
artifact is a lane defect and not a developer-box condition. A gate that cannot
read its input must not report green -- the shape open-debt item 413 records,
where an untracked-oracle lane skips quietly and prints pass.
"""

from __future__ import annotations

import ctypes
import itertools
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
#
# Revision 15 is such a bump: `wz_capi_c_config_disposition` gained a fourth answer
# (`WZ_CAPI_C_CONFIG_NOT_IN_BUILD`) and `wz_capi_c_config_honoured` lists the keys of the build,
# without the keys of a capability it was built without. No symbol moved.
#
# Revision 16 is such a bump too: the clock rule `wz_capi_c.h` states changed. `z_timestamp_new`
# gives a program the node clock's time whatever its standing, and the clock-quality-stamping
# policy holds back only the data the node stamps. No symbol moved.
#
# Each door maps to the revision that first exported it, so a consumer reads here
# what its pinned revision can call (`--history` prints the table by revision)
# and a finding names the revision of the door it is about. The numbers were
# DERIVED: for each door, the commit that first wrote it into this file (`git log
# --reverse -S'"<door>"' -- scripts/lib/capi_c_abi_pin.py`) and
# `EXPECTED_REVISION` as that commit left the file (`git show
# <commit>:scripts/lib/capi_c_abi_pin.py`); this gate made the two move in one
# commit from its first day. The doors of the file's first commit are 1, the
# revision that commit introduced with the revision door. A new door is pinned at
# the revision its own commit moves `EXPECTED_REVISION` to, which `pin_findings`
# holds.
EXPECTED_REVISION = 16
EXPECTED_SYMBOLS: dict[str, int] = {
    # R2301 (item 634) — the revision door itself.
    "wz_capi_c_abi_version": 1,
    # Revision 14 — the sender of a declared segment profile (`segment-sender`, off by default and
    # on in the lane's build): the owned handle's set, the put options' default, the two doors that
    # hand the pieces on (to a publisher, to a callback), and the internal pair.
    "wz_capi_c_segment_sender_new": 14,
    "wz_capi_c_segment_put_options_default": 14,
    "wz_capi_c_segment_sender_put": 14,
    "wz_capi_c_segment_sender_split": 14,
    "wz_capi_c_segment_sender_next": 14,
    "wz_capi_c_segment_sender_set": 14,
    "wz_capi_c_segment_sender_loan": 14,
    "wz_capi_c_segment_sender_drop": 14,
    "wz_capi_c_internal_segment_sender_null": 14,
    "wz_capi_c_internal_segment_sender_check": 14,
    # Revision 13 — the links of a liveliness token and a liveliness subscriber (`switch-doors`).
    "wz_capi_c_liveliness_declare_token_ext": 13,
    "wz_capi_c_liveliness_declare_subscriber_ext": 13,
    # Revision 12 — the statements of a call beyond the zenoh-c options: the links an entity may
    # use, a publish's retry and all-or-none form, a query's target node (`switch-doors`, off by
    # default and on in the lane's build). The three `_default` functions, then the seven doors.
    "wz_capi_c_entity_ext_default": 12,
    "wz_capi_c_publish_ext_default": 12,
    "wz_capi_c_query_ext_default": 12,
    "wz_capi_c_put_ext": 12,
    "wz_capi_c_delete_ext": 12,
    "wz_capi_c_declare_publisher_ext": 12,
    "wz_capi_c_get_ext": 12,
    "wz_capi_c_declare_querier_ext": 12,
    "wz_capi_c_declare_subscriber_ext": 12,
    "wz_capi_c_declare_queryable_ext": 12,
    # Revision 11 — the identity a client presents over TLS, made on the computer it runs on
    # (`identity-make`, off by default and on in the lane's build, as the observation plane is).
    "wz_capi_c_identity_make": 11,
    # Revision 10 — a node's lifecycle verbs from a client: the key a verb is asked by and the
    # answer read back (`lifecycle-doors`, off by default and on in the lane's build).
    "wz_capi_c_lifecycle_key": 10,
    "wz_capi_c_lifecycle_read": 10,
    # Revision 9 — the conformance digest of the build (decision C15), in every build.
    "wz_capi_c_conformance_digest": 9,
    # The observation plane (revision 8): the clock a program registers, the event log, the
    # supervisor and the resource snapshot. Each is a feature that is off in a build made as the
    # reference is, so the lane builds the library with all four on (`layer_c1ch_capi_c_config_surface`
    # in run-ci.sh) and the set below is that build's.
    "wz_capi_c_clock_source_register": 8,
    "wz_capi_c_clock_source_unregister": 8,
    "wz_capi_c_clock_report": 8,
    "wz_capi_c_event_emit": 8,
    "wz_capi_c_event_read": 8,
    "wz_capi_c_event_release": 8,
    "wz_capi_c_event_dropped": 8,
    "wz_capi_c_supervision_set_hook": 8,
    "wz_capi_c_supervision_start": 8,
    "wz_capi_c_supervision_feed": 8,
    "wz_capi_c_supervision_stop": 8,
    "wz_capi_c_supervision_check": 8,
    "wz_capi_c_supervision_healthy": 8,
    "wz_capi_c_supervision_state": 8,
    "wz_capi_c_snapshot_set_source": 8,
    "wz_capi_c_snapshot_poll": 8,
    "wz_capi_c_snapshot_size": 8,
    "wz_capi_c_snapshot_read": 8,
    # R311y540 — the drop-in's half of the layout gate.
    "wz_capi_c_layout": 1,
    "wz_capi_c_layout_name": 1,
    # R2172 (item 548) — which config keys wz's JSON5 reader honours.
    "wz_capi_c_config_honoured": 1,
    "wz_capi_c_config_honoured_count": 1,
    # R2797 — the same question asked BY NAME, in
    # three words. The two doors above enumerate, and the honoured set is
    # infinite, so an enumeration could never be the whole answer.
    "wz_capi_c_config_disposition": 2,
    # R2300 (item 631) — emitting a stock-zenoh config and judging one (`config-verdict`, on by
    # default, as are the rows doors and `wz_capi_c_config_device_requires` below).
    "wz_capi_c_config_to_json5": 1,
    "wz_capi_c_config_validate": 1,
    "wz_capi_c_config_validate_for_build": 1,
    "wz_capi_c_config_validate_topology": 1,
    "wz_capi_c_config_validate_topology_with_external": 1,
    "wz_capi_c_config_link_scheme": 1,
    "wz_capi_c_config_link_scheme_count": 1,
    "wz_capi_c_config_zenoh_link_scheme": 1,
    "wz_capi_c_config_zenoh_link_scheme_count": 1,
    # R2932 — zenoh-ext's group membership (revision 3). The pin reads the
    # DEFAULT build, which is the unstable arm these doors live on.
    "wz_capi_c_member_options_default": 3,
    "wz_capi_c_member_new": 3,
    "wz_capi_c_member_id": 3,
    "wz_capi_c_member_info": 3,
    "wz_capi_c_member_lease_ms": 3,
    "wz_capi_c_member_liveliness": 3,
    "wz_capi_c_member_refresh_ratio": 3,
    "wz_capi_c_member_loan": 3,
    "wz_capi_c_member_clone": 3,
    "wz_capi_c_member_drop": 3,
    "wz_capi_c_internal_member_null": 3,
    "wz_capi_c_internal_member_check": 3,
    "wz_capi_c_closure_member": 3,
    "wz_capi_c_internal_closure_member_null": 3,
    "wz_capi_c_internal_closure_member_check": 3,
    "wz_capi_c_closure_member_loan": 3,
    "wz_capi_c_closure_member_call": 3,
    "wz_capi_c_closure_member_drop": 3,
    "wz_capi_c_closure_group_event": 3,
    "wz_capi_c_internal_closure_group_event_null": 3,
    "wz_capi_c_internal_closure_group_event_check": 3,
    "wz_capi_c_closure_group_event_loan": 3,
    "wz_capi_c_closure_group_event_call": 3,
    "wz_capi_c_closure_group_event_drop": 3,
    "wz_capi_c_group_event_kind": 3,
    "wz_capi_c_group_event_member_id": 3,
    "wz_capi_c_group_event_member": 3,
    "wz_capi_c_group_join": 3,
    "wz_capi_c_group_group_id": 3,
    "wz_capi_c_group_local_member_id": 3,
    "wz_capi_c_group_size": 3,
    "wz_capi_c_group_view": 3,
    "wz_capi_c_group_leader": 3,
    "wz_capi_c_group_subscribe": 3,
    "wz_capi_c_group_wait_for_view_size": 3,
    "wz_capi_c_group_loan": 3,
    "wz_capi_c_group_drop": 3,
    "wz_capi_c_internal_group_null": 3,
    "wz_capi_c_internal_group_check": 3,
    # The config verdict as ROWS (revision 4): a table of
    # (variant, node, key path, endpoint) read a column at a time from an owned
    # handle, for a caller that attaches each reason to the field it is about.
    # The three doors, then the handle's own set, then one accessor per column.
    "wz_capi_c_config_validate_rows": 4,
    "wz_capi_c_config_validate_for_build_rows": 4,
    "wz_capi_c_config_validate_topology_rows": 4,
    "wz_capi_c_config_verdict_len": 4,
    "wz_capi_c_config_verdict_finding_count": 4,
    "wz_capi_c_config_verdict_row_finding": 4,
    "wz_capi_c_config_verdict_row_variant": 4,
    "wz_capi_c_config_verdict_row_message": 4,
    "wz_capi_c_config_verdict_row_node": 4,
    "wz_capi_c_config_verdict_row_key": 4,
    "wz_capi_c_config_verdict_row_endpoint": 4,
    "wz_capi_c_config_verdict_loan": 4,
    "wz_capi_c_config_verdict_drop": 4,
    "wz_capi_c_internal_config_verdict_null": 4,
    "wz_capi_c_internal_config_verdict_check": 4,
    # The sender of an end-to-end protected message (revision 5): an owned
    # handle that keeps the message's counter. Ungated, like the config verdict.
    "wz_capi_c_e2e_sender_new": 5,
    "wz_capi_c_e2e_sender_wrap": 5,
    "wz_capi_c_e2e_sender_next": 5,
    "wz_capi_c_e2e_sender_set": 5,
    "wz_capi_c_e2e_sender_loan": 5,
    "wz_capi_c_e2e_sender_drop": 5,
    "wz_capi_c_internal_e2e_sender_null": 5,
    "wz_capi_c_internal_e2e_sender_check": 5,
    # What one message may weigh (revision 6), asked before it is sent. Ungated.
    "wz_capi_c_session_max_message_bytes": 6,
    # What an open of a config would ask of the operating system (revision 7), as the manifest's
    # facility vocabulary. Ungated.
    "wz_capi_c_config_device_requires": 7,
}

PREFIX = "wz_capi_c_"

#: R2309 (item 637) — the profiles this pin must be shown, DECLARED here and
#: never read off the arguments. A required set derived from what the caller
#: happened to pass is satisfied by construction and can never fail, which is
#: the baseline trap R2300 named. Adding a profile to the lane means adding it
#: here, in the same edit, or the lane is proving less than it looks.
REQUIRED_PROFILES = frozenset({"debug", "release"})


class Fatal(Exception):
    """A derivation that cannot be made. Never a silent pass."""


def profile_of(cdylib: pathlib.Path) -> str:
    """The cargo profile a `crates/target/<profile>/lib*.so` path names.

    Read from the PATH rather than from the file, because that is what the
    lane controls and what a reviewer of `run-ci.sh` can check. A path that
    does not sit under a target profile directory is a Fatal: guessing would
    let two copies of one profile read as two profiles.
    """
    parent = cdylib.parent.name
    if cdylib.parent.parent.name != "target" or not parent:
        raise Fatal(
            f"{cdylib} does not sit in `crates/target/<profile>/`, so which "
            f"cargo profile built it cannot be read from its path. This gate "
            f"compares profiles; one it cannot name it must not accept."
        )
    return parent


def profile_findings(by_profile: dict[str, set[str]]) -> list[str]:
    """Whether the wz-own door set is the SAME in every profile shown.

    A pure function over sets so the selftest can drive it with shapes no
    build on this machine produces -- in particular the one the pre-R2309
    reader was blind to: a door that debug exports and release does not.
    """
    out: list[str] = []
    missing = sorted(REQUIRED_PROFILES - set(by_profile))
    if missing:
        out.append(
            f"profile(s) {', '.join(missing)} were not shown to this gate. The "
            f"pin requires {', '.join(sorted(REQUIRED_PROFILES))} because a set "
            f"read from one build is a claim about that build and not about the "
            f"library -- `lto` runs in release and not in debug, so exactly one "
            f"of them can see a door LTO drops."
        )
    for left, right in itertools.combinations(sorted(by_profile), 2):
        for name in sorted(by_profile[left] - by_profile[right]):
            out.append(
                f"{name} is exported by the {left} build and NOT by the {right} "
                f"build. The wz-own door set is a property of the library, not "
                f"of a profile; a consumer linking the {right} build cannot call "
                f"a door the {left} build advertises."
            )
        for name in sorted(by_profile[right] - by_profile[left]):
            out.append(
                f"{name} is exported by the {right} build and NOT by the {left} "
                f"build. The wz-own door set is a property of the library, not "
                f"of a profile; a consumer linking the {left} build cannot call "
                f"a door the {right} build advertises."
            )
    return out


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


def pin_findings(pinned: dict[str, int], pinned_revision: int) -> list[str]:
    """What is wrong with the table itself, with no artifact to read: a door
    pinned at a revision the pin has not reached, or below the first. A revision
    that brought no door is not a finding, since a memory-rule change moves the
    revision alone."""
    findings = []
    for name, since in sorted(pinned.items()):
        if since > pinned_revision:
            findings.append(
                f"{name} is pinned since revision {since}, after the pinned "
                f"revision {pinned_revision}"
            )
        elif since < 1:
            findings.append(f"{name} is pinned since revision {since}; revisions start at 1")
    return findings


def drift_findings(
    built: set[str], revision: int, pinned: dict[str, int], pinned_revision: int
) -> list[str]:
    """Each door the artifact and the pin disagree about, with its revision.

    A pinned door the build lost names the revision that promised it, so the
    reader knows which consumers it breaks. An exported door nobody pinned is
    named with the revision it has to be pinned at: the one the build answers
    when the revision has moved, the next one when it has not, because then the
    move is what is missing -- a new door under the old revision is a library
    whose version cannot answer the only question a new door raises.
    """
    lines = []
    new_at = revision if revision > pinned_revision else pinned_revision + 1
    for name in sorted(built - set(pinned)):
        lines.append(
            f"{name} is exported and NOT in the pin -- pin it as \"{name}\": "
            f"{new_at} and move EXPECTED_REVISION to {new_at} in the same edit"
        )
    for name in sorted(set(pinned) - built):
        lines.append(
            f"{name} is in the pin (since revision {pinned[name]}) and NOT "
            "exported. A removal is an ABI event too: drop it from "
            "EXPECTED_SYMBOLS and move EXPECTED_REVISION in the same edit."
        )
    return lines


def history(pinned: dict[str, int]) -> str:
    """The table a consumer reads: each revision and the doors it brought."""
    by_revision: dict[int, list[str]] = {}
    for name, since in pinned.items():
        by_revision.setdefault(since, []).append(name)
    return "\n".join(
        f"revision {since}: {', '.join(sorted(by_revision[since]))}"
        for since in sorted(by_revision)
    )


def run(cdylibs: list[pathlib.Path]) -> int:
    findings: list[str] = list(pin_findings(EXPECTED_SYMBOLS, EXPECTED_REVISION))

    by_profile: dict[str, set[str]] = {}
    revisions: dict[str, int] = {}
    for cdylib in cdylibs:
        if not cdylib.is_file():
            print(
                f"capi-c-abi-pin: FAIL -- {cdylib} is absent. The lane must "
                "build the cdylib before this gate runs; a symbol set read from "
                "nothing is not a symbol set.",
                file=sys.stderr,
            )
            return 1
        profile = profile_of(cdylib)
        if profile in by_profile:
            # Two paths naming one profile would satisfy REQUIRED_PROFILES by
            # arithmetic while proving nothing about the other one.
            print(
                f"capi-c-abi-pin: FAIL -- profile {profile} was passed twice. "
                "Each profile must be shown exactly once, or a count of two "
                "arguments reads as a comparison that never happened.",
                file=sys.stderr,
            )
            return 1
        by_profile[profile] = artifact_symbols(cdylib)
        revisions[profile] = artifact_revision(cdylib)

    # The SOURCE corner, from the gate that already derives it. Imported, never
    # reimplemented -- see the header.
    # R2773 -- the src is DERIVED by the same gate, never spelled here. R2766
    # widened `exported` to take it and this call kept the old arity, so this
    # line raised TypeError on hosted run 35558290992 and Layer C1ch graded
    # nothing at all. Asking `door_gate` for both halves is what stops the
    # next widening from splitting them again.
    from_source = door_gate.exported(
        PREFIX, door_gate.src_of(door_gate.surface_for(PREFIX))
    )
    if not from_source:
        findings.append(
            "the source derivation returned no door, so its agreement with the "
            "artifact means nothing."
        )

    findings.extend(profile_findings(by_profile))

    for profile in sorted(by_profile):
        built = by_profile[profile]
        if not built:
            findings.append(
                f"the {profile} artifact defines no `{PREFIX}*` symbol at all. "
                "Either `nm` has stopped being read or the library stopped "
                "exporting wz's own doors; an empty population agrees with any "
                "pin."
            )

        for name in sorted(built - from_source):
            findings.append(
                f"{name} is EXPORTED by the {profile} artifact and found in no "
                "tracked source. The source scanner has drifted from what "
                "actually ships."
            )
        for name in sorted(from_source - built):
            findings.append(
                f"{name} is declared `#[no_mangle]` in source and ABSENT from "
                f"the {profile} artifact. A cfg or LTO removed it, so a consumer "
                "linking against this build cannot call it however the source "
                "reads."
            )

        got = revisions[profile]
        findings.extend(
            f"the {profile} build: {line}"
            for line in drift_findings(built, got, EXPECTED_SYMBOLS, EXPECTED_REVISION)
        )

        if got != EXPECTED_REVISION:
            findings.append(
                f"the {profile} library reports revision {got} and the pin says "
                f"{EXPECTED_REVISION}. A revision may move on its own (the "
                "memory rule can change without a symbol changing), but it must "
                "move HERE too, or it moved for a reason nobody wrote down."
            )

    header_text = HEADER.read_text(errors="replace")
    said = header_revision(header_text)
    for profile in sorted(revisions):
        if said != revisions[profile]:
            findings.append(
                f"{HEADER.relative_to(ROOT)} says WZ_CAPI_C_ABI_REVISION is "
                f"{said} and the {profile} library answers {revisions[profile]}. "
                "The pair exists so a CONSUMER can detect a library it was not "
                "compiled against; disagreeing at rest makes that check "
                "meaningless before anyone runs it."
            )

    if findings:
        print("capi-c-abi-pin: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1

    covered = next(iter(by_profile.values()))
    print(
        f"capi-c-abi-pin: OK -- revision {said} covers {len(covered)} "
        f"`{PREFIX}*` door(s), agreed by the sources, the header and the "
        f"{', '.join(sorted(by_profile))} artifacts, whose sets are identical"
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

    # The revision arms: a finding names the revision of the door it is about,
    # an impossible table is refused, and the table this file pins is not.
    pinned = {"wz_capi_c_a": 1, "wz_capi_c_b": 3}
    drift_cases = [
        ({"wz_capi_c_a", "wz_capi_c_b"}, 3, []),
        (
            {"wz_capi_c_a", "wz_capi_c_b", "wz_capi_c_c"},
            4,
            ['"wz_capi_c_c": 4 and move EXPECTED_REVISION to 4'],
        ),
        (
            {"wz_capi_c_a", "wz_capi_c_b", "wz_capi_c_c"},
            3,
            ['"wz_capi_c_c": 4 and move EXPECTED_REVISION to 4'],
        ),
        ({"wz_capi_c_a"}, 3, ["wz_capi_c_b is in the pin (since revision 3)"]),
    ]
    for built, revision, wanted in drift_cases:
        got = drift_findings(built, revision, pinned, 3)
        if len(got) != len(wanted) or not all(w in g for w, g in zip(wanted, got)):
            print(
                f"selftest: doors {sorted(built)} at revision {revision} gave "
                f"{got}, expected lines containing {wanted}",
                file=sys.stderr,
            )
            return 1
    for table, revision, count in [
        ({"wz_capi_c_a": 1, "wz_capi_c_b": 3}, 3, 0),
        ({"wz_capi_c_a": 1, "wz_capi_c_b": 4}, 3, 1),
        ({"wz_capi_c_a": 0}, 3, 1),
    ]:
        if len(pin_findings(table, revision)) != count:
            print(f"selftest: table {table} at revision {revision} misjudged", file=sys.stderr)
            return 1
    if history({"wz_capi_c_b": 3, "wz_capi_c_a": 1}) != (
        "revision 1: wz_capi_c_a\nrevision 3: wz_capi_c_b"
    ):
        print("selftest: the history table", file=sys.stderr)
        return 1
    own = pin_findings(EXPECTED_SYMBOLS, EXPECTED_REVISION)
    if own:
        print("selftest: this file's own table:\n  " + "\n  ".join(own), file=sys.stderr)
        return 1

    # R2309 (item 637) — the profile axis. Driven over SETS, because the shape
    # that matters is one no build on this machine currently produces: a door
    # present in one profile and absent from the other. That is precisely what
    # the pre-R2309 reader, holding a single debug artifact, could not see.
    if profile_of(pathlib.Path("crates/target/release/libwz_capi_c.so")) != "release":
        print("selftest: the profile reader misread a target path", file=sys.stderr)
        return 1
    # Under WZ_ARTIFACT_ROOT the artifact is the mirrored path below the root.
    if profile_of(pathlib.Path("/srv/wz/crates/target/debug/libwz_capi_c.so")) != "debug":
        print("selftest: the profile reader misread a path under an artifact root",
              file=sys.stderr)
        return 1
    for bad in ["libwz_capi_c.so", "crates/target/libwz_capi_c.so", "/tmp/x/lib.so"]:
        try:
            profile_of(pathlib.Path(bad))
        except Fatal:
            pass
        else:
            print(f"selftest: a non-profile path was accepted: {bad}", file=sys.stderr)
            return 1

    both = {"debug": {"wz_capi_c_a"}, "release": {"wz_capi_c_a"}}
    if profile_findings(both):
        print("selftest: identical sets in both profiles were reported", file=sys.stderr)
        return 1
    # A door LTO dropped: present in debug, gone from release.
    dropped = {"debug": {"wz_capi_c_a", "wz_capi_c_b"}, "release": {"wz_capi_c_a"}}
    said = profile_findings(dropped)
    if not any("wz_capi_c_b" in f and "release" in f for f in said):
        print("selftest: a door missing from release was not reported", file=sys.stderr)
        return 1
    # And the reverse, which is an ABI event too and must not be assumed away.
    gained = {"debug": {"wz_capi_c_a"}, "release": {"wz_capi_c_a", "wz_capi_c_b"}}
    if not any("wz_capi_c_b" in f and "debug" in f for f in profile_findings(gained)):
        print("selftest: a door missing from debug was not reported", file=sys.stderr)
        return 1
    # One profile is not a comparison. The pre-R2309 lane passed exactly this.
    if not any("release" in f for f in profile_findings({"debug": {"wz_capi_c_a"}})):
        print("selftest: a single profile was accepted as a pin", file=sys.stderr)
        return 1

    print("capi-c-abi-pin: selftest OK")
    return 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--selftest"]
    try:
        if "--selftest" in sys.argv[1:]:
            sys.exit(selftest())
        if sys.argv[1:] == ["--history"]:
            print(history(EXPECTED_SYMBOLS))
            sys.exit(0)
        if not args:
            print(
                "usage: capi_c_abi_pin.py <libwz_capi_c.so>... | --selftest | --history\n"
                "  one path per cargo profile; "
                f"{', '.join(sorted(REQUIRED_PROFILES))} are required",
                file=sys.stderr,
            )
            sys.exit(2)
        sys.exit(run([pathlib.Path(a) for a in args]))
    except Fatal as e:
        print(f"capi-c-abi-pin: FAIL -- {e}", file=sys.stderr)
        sys.exit(1)
