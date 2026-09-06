#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2371 (no register item) -- the `transport-stats` COUNTER SURFACE must be
upstream's, and it must stay upstream's after upstream moves.

The citation is `no register item` in the sense `oracle_pin_gate.py` uses: this
answers the `transport-stats` atom's residual directly rather than a numbered
open-debt row, so there is no store `debt-` id for `gate_provenance_lint.py` to
resolve. It is named in prose here instead.

## The class this exists for, and why a test could not hold it

R2332 measured this workspace's stats surface against the pin and found four
flat counters where upstream had rebuilt the whole thing as a label-indexed
registry: a MEDIUM split on the network-message counter, a SPACE split on four
payload kinds, and three interceptor-drop counters. None of that was visible
from inside the tree -- every wz test passed, because every wz test was written
against the four counters wz had.

That is the shape a unit test structurally cannot catch: the tree agreeing with
itself. The population has to come from UPSTREAM, and it has to be DERIVED from
upstream's own declaration rather than transcribed into a list here -- a list
here would be a second copy of upstream's surface, going stale exactly the way
the four counters did.

## Both sides are derived, and that is the point

  UPSTREAM  the `stats_default!` invocations inside upstream's `init_stats`
            declare every counter and its axis. Parsed from the pinned
            checkout; the local bindings the macro splices (`..payload_stats`,
            `..link_stats`) are resolved, so the set is the FLATTENED one the
            JSON actually carries.

  WZ        `DirectionReport`'s FIELDS plus the axis enums' `label()` arms.
            An array-typed field IS an axis (`[usize; StatMedium::COUNT]` is
            the medium split), and the payload field's two-dimensional type is
            what expands to the per-kind, per-space family.

Neither side is a hand-written list of counter names, so a gate that passes
means the two DERIVATIONS agree -- not that someone wrote the same names twice.

## Zero population is a FAILURE, not a pass

Both parses must yield counters. A gate whose population is empty reports green
for every possible tree, which is the trap this workspace has walked into often
enough to name it: a check that reads nothing is indistinguishable from a check
that found nothing wrong. An upstream restructure that this parser no longer
understands therefore REDS rather than silently passing.

## SKIP vs FAIL when the checkout is absent

The upstream half needs a real checkout, which is machine-local state (the
project guide's External references rule: never inherit "absent" from a note,
establish it). Absent, this SKIPs -- the arming flag `--require` is what a
hosted lane sets to turn that into a hard failure, the same split
`sn_resolution_words.py` uses for the same reason.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Upstream's stats crate, built from SEGMENTS rather than written as one
#: string. The path is deliberately not spelled as a literal anywhere in this
#: file: `upstream_citation_anchor_gate.py` scans tracked files, and a path
#: literal here would enter its BARE population as though someone had made a
#: citation -- moving a budget this file has no business moving. The same reason
#: `sn_resolution_words.py` builds its own upstream path this way.
UPSTREAM_REL = pathlib.Path("commons", "zenoh-stats", "src", "stats.rs")

#: The wz side, which is in-tree and therefore an ordinary path.
WZ_STATS_REL = pathlib.Path("crates", "wz-session-core", "src", "stats.rs")

#: One `stats_default!(...)` invocation and the local name it is bound to.
_DEFAULT_BIND_RE = re.compile(
    r"let\s+(?P<bind>\w+)\s*=\s*stats_default!\s*\((?P<args>.*?)\)\s*;",
    re.S,
)

#: One entry inside such an invocation: either `name`, `name <axis>`, or a
#: `..other` splice of a previously bound invocation.
_ENTRY_RE = re.compile(r"^\s*(?:\.\.(?P<splice>\w+)|(?P<name>\w+)(?:\s+(?P<axis>\w+))?)\s*$")

#: `DirectionReport`'s body, which is wz's declaration of the same surface.
_WZ_STRUCT_RE = re.compile(
    r"pub struct DirectionReport\s*\{(?P<body>.*?)\n\}", re.S
)

#: One field of it. The doc comments between fields are skipped by the parse
#: rather than by a regex that tries to span them.
_WZ_FIELD_RE = re.compile(r"^\s{4}pub (?P<name>\w+):\s*(?P<ty>[^,]+),\s*$", re.M)

#: `StatMessage`'s label arms -- the four payload kinds, derived from the enum
#: rather than listed, so a fifth kind reaches this gate with no edit here.
_WZ_LABEL_ARMS_RE = re.compile(
    r"impl StatMessage \{.*?pub const fn label\(self\) -> &'static str \{"
    r"(?P<arms>.*?)\n        \}",
    re.S,
)
_WZ_ARM_RE = re.compile(r"StatMessage::\w+\s*=>\s*\"(?P<label>\w+)\"")


def upstream_source() -> pathlib.Path | None:
    """Upstream's stats module, wherever this machine keeps it."""
    roots: list[pathlib.Path] = []
    env = os.environ.get("WZ_ZENOH_SRC")
    if env:
        roots.append(pathlib.Path(env))
    roots.append(pathlib.Path.home() / "zenoh-ref")
    for root in roots:
        cand = root / UPSTREAM_REL
        if cand.is_file():
            return cand
    return None


def upstream_surface(text: str) -> dict[str, str]:
    """`{counter name: axis}` as upstream DECLARES it, splices resolved.

    The axis is `""` for a plain counter, else the axis word upstream writes
    after the name (`space` / `medium`). Direction prefixes are NOT applied
    here -- upstream's macro adds `tx_` and `rx_` to every entry, so they are a
    property of the whole set rather than of an entry, and
    [`counter_names`] is where both sides get them.
    """
    binds: dict[str, dict[str, str]] = {}
    for m in _DEFAULT_BIND_RE.finditer(text):
        entries: dict[str, str] = {}
        for raw in m.group("args").split(","):
            if not raw.strip():
                continue
            em = _ENTRY_RE.match(raw)
            if em is None:
                # An entry this parser does not understand is a RESTRUCTURE, and
                # skipping it would shrink the population silently.
                raise ValueError(f"unparsed stats_default! entry: {raw.strip()!r}")
            if em.group("splice"):
                spliced = binds.get(em.group("splice"))
                if spliced is None:
                    raise ValueError(f"splice of an unbound name: {em.group('splice')!r}")
                entries.update(spliced)
                continue
            entries[em.group("name")] = em.group("axis") or ""
        binds[m.group("bind")] = entries
    if not binds:
        return {}
    # The LAST binding is the flattened one (upstream builds the transport set
    # by splicing the payload and link sets into it), and it is the set the
    # per-transport JSON carries.
    return binds[list(binds)[-1]]


def wz_surface(text: str) -> dict[str, str]:
    """`{counter name: axis}` as wz declares it, derived from the types."""
    sm = _WZ_STRUCT_RE.search(text)
    if sm is None:
        raise ValueError("DirectionReport not found -- wz restructured its report type")
    lm = _WZ_LABEL_ARMS_RE.search(text)
    if lm is None:
        raise ValueError("StatMessage::label not found -- wz restructured its axes")
    kinds = [a.group("label") for a in _WZ_ARM_RE.finditer(lm.group("arms"))]
    if not kinds:
        raise ValueError("StatMessage declares no payload kind")

    out: dict[str, str] = {}
    for f in _WZ_FIELD_RE.finditer(sm.group("body")):
        name, ty = f.group("name"), f.group("ty").strip()
        if "PayloadCounters" in ty:
            # The two-dimensional payload field expands to the per-kind family,
            # each split on the SPACE axis.
            for kind in kinds:
                out[f"z_{kind}_msgs"] = "space"
                out[f"z_{kind}_pl_bytes"] = "space"
        elif ty.startswith("[") and "StatMedium::COUNT" in ty:
            out[name] = "medium"
        elif ty.startswith("["):
            raise ValueError(f"{name}: an array field on an axis this gate cannot name ({ty})")
        else:
            out[name] = ""
    return out


def counter_names(surface: dict[str, str]) -> set[tuple[str, str]]:
    """`(name, axis)` for both directions -- the comparable form."""
    return {
        (f"{d}_{name}", axis)
        for name, axis in surface.items()
        for d in ("tx", "rx")
    }


def grade(upstream_text: str, wz_text: str) -> tuple[int, list[str]]:
    """The whole verdict over TEXT, so the selftest drives the shipped path."""
    report: list[str] = []
    try:
        theirs = counter_names(upstream_surface(upstream_text))
        ours = counter_names(wz_surface(wz_text))
    except ValueError as exc:
        return 1, [f"  transport-stats-surface FAIL -- {exc}"]

    if not theirs:
        return 1, [
            "  transport-stats-surface FAIL -- upstream parsed to NO counter. Its"
            " stats module may have been restructured; read it before changing"
            " anything here. A population of zero would otherwise report green."
        ]
    if not ours:
        return 1, [
            "  transport-stats-surface FAIL -- wz parsed to NO counter, so this"
            " run compared nothing."
        ]

    missing = sorted(theirs - ours)
    extra = sorted(ours - theirs)
    rc = 0
    if missing:
        rc = 1
        report.append(
            f"  transport-stats-surface FAIL -- {len(missing)} counter(s) upstream"
            " declares and wz does not carry:"
        )
        for name, axis in missing:
            report.append(f"    {name}{' {' + axis + '}' if axis else ''}")
    if extra:
        rc = 1
        report.append(
            f"  transport-stats-surface FAIL -- {len(extra)} counter(s) wz carries"
            " and upstream does not declare. A wz-local counter must not sit in"
            " this surface under an upstream-shaped name:"
        )
        for name, axis in extra:
            report.append(f"    {name}{' {' + axis + '}' if axis else ''}")
    report.append(
        f"  transport-stats-surface: {len(theirs)} counter(s) declared upstream,"
        f" {len(ours)} carried by wz, {len(theirs & ours)} agreeing"
    )
    return rc, report


def cmd_check(require: bool) -> int:
    src = upstream_source()
    if src is None:
        if require:
            print(
                "  transport-stats-surface FAIL -- required, and no zenoh-stats"
                " source was found (set WZ_ZENOH_SRC, or keep a checkout at"
                " ~/zenoh-ref).",
                file=sys.stderr,
            )
            return 1
        print(
            "  transport-stats-surface SKIP -- no zenoh-stats source on this"
            " machine. The in-tree derivation still holds the render together;"
            " what is unchecked here is whether it is still UPSTREAM's set."
        )
        return 0
    wz = REPO_ROOT / WZ_STATS_REL
    rc, report = grade(src.read_text(encoding="utf-8"), wz.read_text(encoding="utf-8"))
    for line in report:
        print(line, file=sys.stderr if rc else sys.stdout)
    return rc


def cmd_selftest() -> int:
    """Drive `grade` with mutated inputs -- both directions, and the empties.

    Each case states what it BREAKS, and the gate must red for it. A case that
    passes here without the mutation being the reason is the failure mode this
    workspace keeps rediscovering, so the green case is included too.
    """
    good_up = (
        "pub(crate) fn init_stats(json: &mut serde_json::Value, keys: &[String]) {\n"
        "    let link_stats = stats_default!(bytes, t_msgs, n_msgs medium, n_dropped);\n"
        "    let payload_stats = stats_default!(\n"
        "        z_put_msgs space,\n"
        "        z_put_pl_bytes space,\n"
        "    );\n"
        "    let transport_stats = stats_default!(\n"
        "        low_pass_dropped_msgs,\n"
        "        ..payload_stats,\n"
        "        ..link_stats,\n"
        "    );\n"
        "}\n"
    )
    good_wz = (
        "pub struct DirectionReport {\n"
        "    pub bytes: usize,\n"
        "    pub t_msgs: usize,\n"
        "    pub n_msgs: [usize; StatMedium::COUNT],\n"
        "    pub n_dropped: usize,\n"
        "    pub payload: [[PayloadCounters; StatSpace::COUNT]; StatMessage::COUNT],\n"
        "    pub low_pass_dropped_msgs: usize,\n"
        "}\n"
        "impl StatMessage {\n"
        "    pub const fn label(self) -> &'static str {\n"
        "        match self {\n"
        "            StatMessage::Put => \"put\",\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

    cases: list[tuple[str, str, str, int]] = [
        ("the unmutated pair agrees", good_up, good_wz, 0),
        (
            "upstream adds a counter wz does not carry",
            good_up.replace("        low_pass_dropped_msgs,\n",
                            "        low_pass_dropped_msgs,\n        n_brand_new,\n"),
            good_wz,
            1,
        ),
        (
            "wz drops a counter upstream declares",
            good_up,
            good_wz.replace("    pub n_dropped: usize,\n", ""),
            1,
        ),
        (
            "wz invents a counter upstream does not declare",
            good_up,
            good_wz.replace("    pub n_dropped: usize,\n",
                            "    pub n_dropped: usize,\n    pub wz_invented: usize,\n"),
            1,
        ),
        (
            "an AXIS is dropped on the wz side (the split silently flattens)",
            good_up,
            good_wz.replace("    pub n_msgs: [usize; StatMedium::COUNT],\n",
                            "    pub n_msgs: usize,\n"),
            1,
        ),
        (
            "a payload KIND disappears from the wz axis enum",
            good_up,
            good_wz.replace("            StatMessage::Put => \"put\",\n", ""),
            1,
        ),
        ("upstream parses to nothing", "", good_wz, 1),
        ("wz parses to nothing", good_up, "", 1),
        (
            "an upstream entry this parser cannot read is a RESTRUCTURE, not a skip",
            good_up.replace("        low_pass_dropped_msgs,\n",
                            "        weird = 3 + 4,\n"),
            good_wz,
            1,
        ),
    ]

    failures = 0
    for label, up, wz, want in cases:
        rc, _ = grade(up, wz)
        ok = rc == want
        if not ok:
            failures += 1
        print(f"  [{'ok' if ok else 'FAIL'}] rc={rc} want={want}  {label}")
    if failures:
        print(f"  transport-stats-surface selftest FAIL -- {failures} case(s)",
              file=sys.stderr)
        return 1
    print(f"  transport-stats-surface selftest: {len(cases)} case(s) all as expected")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_mutually_exclusive_group(required=True)
    sub.add_argument("--check", action="store_true",
                     help="compare the pinned upstream surface against wz's")
    sub.add_argument("--selftest", action="store_true",
                     help="drive the grader with mutated inputs")
    ap.add_argument("--require", action="store_true",
                    help="with --check: an absent upstream checkout FAILS instead "
                         "of skipping (the hosted arming flag)")
    args = ap.parse_args()
    if args.selftest:
        return cmd_selftest()
    return cmd_check(args.require)


if __name__ == "__main__":
    sys.exit(main())
