#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2142 (no register item) — WHICH axes of the scouting socket can config move,
and which of those are witnessed END-TO-END between two wz nodes.

The citation is `no register item` for the reason `debt_plane_census.py` and
`config_key_fixture_gate.py` both give for theirs: the item this closes --
unregistered open-debt item 225 -- lives in the agent-memory register, which has
no store id for `gate_provenance_lint.py` to resolve. The item is named in prose
throughout this header.

## The question, and why prose kept answering it wrongly

Item 225 said "the moved scouting socket has no both-ended lane". Establishing
that meant listing what "the scouting socket" even HAS -- group, port, iface,
ttl, extra joins -- and then saying which are proven. That list was never
written down, so every round that touched the area re-derived it by reading, and
a reader who stops at `bind_multicast_v4(group, port, ...)` sees TWO axes when
there are FIVE. A count nobody prints is a count that drifts.

## What it DERIVES rather than declares

The axis population is read out of the socket's own surface, never from a list
in this file:

  * the leading scalar parameters of `UdpDriver::bind_multicast_v4` -> `group`,
    `port`;
  * the `pub` fields of `struct McastSocketConfig` -> `iface`, `ttl`,
    `extra_joins`.

⛔ A derivation of ZERO is a FAILURE, not an empty pass. Both halves must yield
at least one axis; a parse that silently found nothing would report "everything
covered" about a population it never read, which is the one defect a gate must
not have.

## The ratchet, in both directions

* An axis that is derived but carries NO verdict below FAILS. Adding a field to
  `McastSocketConfig` therefore arrives UNJUDGED and stops the push, rather than
  quietly widening the denominator while the numerator stands still.
* A verdict naming an axis that is NOT derived FAILS. A renamed or deleted field
  leaves a verdict pointing at nothing, which is how a coverage table rots.
* Every anchor -- the witness of a covered axis, and the `nearest` of a skipped
  one -- must RESOLVE to a real `fn` in the tree. Renaming a test breaks this
  gate rather than silently converting a claim into fiction. This is
  `config_key_fixture_gate.py`'s anchor rule, for the same reason.

## ⚠ Why the breakdown is printed and not just the total

`2/5 covered` reads like a shortfall to fix. Three of the five are NOT
shortfalls -- they are decisions with stated preconditions this repository's
loopback CI cannot meet, and one of them (`iface`) has a witness that is real but
ONE-ENDED. A total hides that distinction; the per-axis lines are the report.
Open-debt item 190 and the R2137 lesson both say the same thing: a skip is a
claim, and a claim gets its reason printed next to it.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
LIB = REPO / "crates" / "wz-runtime-tokio" / "src" / "lib.rs"
# Where an anchor may live: the crate's own unit tests plus every integration
# lane in the tree. Anchors are resolved against ALL of it, so a witness moving
# between files is not a failure -- only its disappearance is.
ANCHOR_ROOTS = (
    REPO / "crates" / "wz-runtime-tokio" / "src",
    REPO / "crates" / "wz-runtime-tokio" / "tests",
    REPO / "crates" / "wz-integration-tests" / "tests",
)

# ── verdicts ────────────────────────────────────────────────────────────────
# kind: "both" (two wz nodes), "one" (real, but only one end is wz),
#       "none" (no end-to-end witness at all).
VERDICTS: dict[str, tuple[str, str | None, str]] = {
    "group": (
        "both",
        "two_nodes_moved_onto_one_socket_find_each_other_and_a_lone_mover_finds_nothing",
        "R2142: two wz nodes both moved -> discovered; only the asker moved -> nothing.",
    ),
    "port": (
        "both",
        "two_nodes_moved_onto_one_socket_find_each_other_and_a_lone_mover_finds_nothing",
        "R2142: same lane's control moves the PORT, which is the axis that isolates "
        "(see moving_only_the_group_leaves_a_responder_reachable_but_moving_the_port_does_not).",
    ),
    "iface": (
        "one",
        "a_multicast_iface_pin_decides_whether_the_group_datagram_arrives",
        "Real delivery A/B on a non-`lo` NIC, but ONE-ENDED: it drives two drivers, "
        "not two nodes. Its own doc argues the cross-impl form CANNOT exist -- a "
        "foreign peer must share the group to interoperate, and sharing the group "
        "installs the host membership that hides the pin.",
    ),
    "ttl": (
        "none",
        "the_send_only_half_carries_the_hop_limit_too",
        "Sockopt readback only. Observing a hop limit end-to-end needs datagrams "
        "crossing routed subnets; a loopback lane has one hop, so there is no "
        "arrangement here in which a wrong TTL and a right one differ.",
    ),
    "extra_joins": (
        "both",
        "a_responder_answers_on_an_extra_joined_group_and_only_because_it_joined_it",
        "R2142: a wz responder given `#join=<g>` answers a Scout addressed to <g>, and "
        "the same responder without the list does not. The control is only meaningful "
        "because nothing else on the host holds <g> -- otherwise IP_MULTICAST_ALL, not "
        "the join, would deliver it.",
    ),
}

COVERED = {"both"}


def read(path: pathlib.Path) -> str:
    if not path.is_file():
        sys.exit(f"scouting-socket-axis-census: FAIL -- {path} is not a file")
    return path.read_text(encoding="utf-8")


def derive_ctor_axes(src: str) -> list[str]:
    """The scalar parameters `bind_multicast_v4` takes before its config struct."""
    m = re.search(
        r"pub async fn bind_multicast_v4\s*\((?P<params>.*?)\)\s*->", src, re.S
    )
    if not m:
        return []
    axes = []
    for raw in m.group("params").split(","):
        raw = raw.strip()
        if not raw or raw.startswith("//"):
            continue
        name, _, ty = raw.partition(":")
        name, ty = name.strip(), ty.strip()
        # The config struct is not an axis -- its FIELDS are, and they are
        # derived separately below.
        if "McastSocketConfig" in ty:
            continue
        if name.isidentifier():
            axes.append(name)
    return axes


def derive_config_axes(src: str) -> list[str]:
    """The `pub` fields of `struct McastSocketConfig`."""
    m = re.search(
        r"pub struct McastSocketConfig<[^>]*>\s*\{(?P<body>.*?)\n\}", src, re.S
    )
    if not m:
        return []
    return re.findall(r"^\s*pub\s+([A-Za-z_][A-Za-z0-9_]*)\s*:", m.group("body"), re.M)


def anchors_present() -> set[str]:
    """Every `fn` name declared anywhere an anchor may live."""
    names: set[str] = set()
    for root in ANCHOR_ROOTS:
        if not root.is_dir():
            continue
        for path in root.rglob("*.rs"):
            names.update(
                re.findall(
                    r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", path.read_text(encoding="utf-8")
                )
            )
    return names


def main() -> int:
    src = read(LIB)
    ctor = derive_ctor_axes(src)
    cfg = derive_config_axes(src)

    failures: list[str] = []
    if not ctor:
        failures.append(
            "derived 0 axes from `bind_multicast_v4`'s signature -- the parse found "
            "nothing, so this gate read no population at all"
        )
    if not cfg:
        failures.append(
            "derived 0 axes from `struct McastSocketConfig` -- same: an empty "
            "population is a broken reader, not a clean tree"
        )

    origin: dict[str, str] = {}
    for a in ctor:
        origin[a] = "bind_multicast_v4 param"
    for a in cfg:
        origin.setdefault(a, "McastSocketConfig field")
    derived = list(origin)

    if failures:
        for f in failures:
            print(f"  scouting-socket-axis-census: FAIL -- {f}", file=sys.stderr)
        return 1

    present = anchors_present()

    unjudged = [a for a in derived if a not in VERDICTS]
    stale = [a for a in VERDICTS if a not in origin]

    rows = []
    for axis in derived:
        # An unjudged axis is reported below, not crashed on: this loop must not
        # be the thing that stops, or the operator gets a traceback where an
        # actionable "judge this axis" belongs. (Probed R2142: it did.)
        if axis not in VERDICTS:
            continue
        kind, anchor, why = VERDICTS[axis]
        if anchor and anchor not in present:
            failures.append(
                f"axis `{axis}` cites `{anchor}`, which is not a fn anywhere under "
                f"the anchor roots -- the witness was renamed or removed and this "
                f"verdict now points at nothing"
            )
        rows.append((axis, origin[axis], kind, anchor, why))

    for axis in unjudged:
        failures.append(
            f"axis `{axis}` ({origin[axis]}) is DERIVED but carries no verdict -- a "
            f"new movable axis arrives unjudged and must be judged, not inherited"
        )
    for axis in stale:
        failures.append(
            f"verdict for `{axis}` names an axis the source no longer has -- the "
            f"table has outlived the struct"
        )

    covered = [r for r in rows if r[2] in COVERED]
    print(
        f"  scouting-socket-axis-census: {len(derived)} movable axis(es) derived "
        f"from the socket's own surface; {len(covered)} witnessed BOTH-ENDED"
    )
    width = max((len(r[0]) for r in rows), default=4)
    for axis, org, kind, anchor, why in rows:
        mark = {"both": "BOTH-ENDED", "one": "one-ended ", "none": "NOT e2e   "}[kind]
        print(f"    {axis.ljust(width)}  {mark}  ({org})")
        print(f"    {' ' * width}    witness: {anchor or '--'}")
        print(f"    {' ' * width}    {why}")
    not_both = [r for r in rows if r[2] not in COVERED]
    if not_both:
        print(
            f"    -- {len(not_both)} axis(es) are NOT both-ended, each with its reason "
            f"above: {', '.join(r[0] for r in not_both)}"
        )

    if failures:
        for f in failures:
            print(f"  scouting-socket-axis-census: FAIL -- {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
