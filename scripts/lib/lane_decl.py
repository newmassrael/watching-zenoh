#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4654 (no register item) -- the lane declaration, `scripts/lib/lanes.toml`: one entry per lane of
`scripts/run-ci.sh`, saying how far the lane's verdict can be trusted and what it reads that its
commands do not say.

RFC 0001 (`docs/rfc/0001-a-lane-lands-alone-and-a-verdict-is-keyed-by-what-it-read.md`)
keys a verdict by the digest of what a lane reads (section 4.2) and lets only some lanes' verdicts
be reused (section 5.5). Both need a fact no command line states: whether the verdict is a function
of the tree (class D), of the tree and a machine (E) or a statistic (S), and which files the lane
reads besides the packages it builds. This module is the one reader of that file; `lanes_gate.py`
holds it to the dispatch table, `lane_digest.py` puts each entry into its lane's key.

## Schema `wz-lanes/1` (stable; a change of shape is a new schema word)

    schema = "wz-lanes/1"

    [[lane]]
    id       = "C1"                       the dispatch id of `run_layer <id> <fn>`, once per file
    fn       = "layer_c1_cargo_test"      the function that dispatch line names
    class    = "D"                        "D", "E" or "S" (RFC 0001 section 5.5)
    reason   = "..."                      E and S only, and required there: what the verdict
                                          depends on that the key does not hold
    nondet   = ["wall-clock"]             S only, and required there: words of NONDET
    decl     = ["docs/.atomic/**"]        optional: globs of tracked files the lane reads that
                                          neither its packages nor its scripts name
    packages = ["crates:*"]               optional: the cargo packages the lane builds when its
                                          commands do not say. "<name>" (a local package of any
                                          workspace), "<ws>:<name>", or "<ws>:*" (every member
                                          of the workspace whose root directory is <ws>)
    legs     = "scripts/lib/x.sh"         optional: a tracked script whose `LEGS=( ... )` rows
                                          (`package|scope|features|...`) are what the lane runs

Every value is on one line (the floor interpreter's reader, `wz_config.read_decl_toml`).

## Interface

    DECL_PATH, SCHEMA, CLASSES, NONDET
    LaneDecl(id, fn, cls, reason, nondet, decl, packages, legs)
    parse(text) -> (list[LaneDecl], list[str])   the entries that read, and one finding per
                                                 breach, each naming the entry and the field
    ids(text) -> list[str]                       every entry's id, read or not
    canonical(entry) -> dict                     the entry as a lane's key holds it
    leg_packages(text) -> list[str]              the package of every row of a LEGS table

  python3 scripts/lib/lane_decl.py --selftest
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NamedTuple

# The floor interpreter's TOML reader is a sibling; the callers may run this isolated (`-I`).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from git_tree import glob_regex  # noqa: E402
from wz_config import read_decl_toml  # noqa: E402

DECL_PATH = "scripts/lib/lanes.toml"
SCHEMA = "wz-lanes/1"
CLASSES = ("D", "E", "S")
#: What an S lane's verdict reads that no key can hold (RFC 0001 section 5.5).
NONDET = ("wall-clock", "host-buffers", "scheduler", "interfaces", "cores")
_KEYS = ("id", "fn", "class", "reason", "nondet", "decl", "packages", "legs")
_ID = re.compile(r"^[A-Za-z0-9]+$")
_FN = re.compile(r"^layer_[a-z0-9_]+$")
_PACKAGE = re.compile(r"^(?:(?P<ws>[A-Za-z0-9_./-]+):)?(?P<name>\*|[A-Za-z0-9_-]+)$")


class LaneDecl(NamedTuple):
    id: str
    fn: str
    cls: str
    reason: str
    nondet: tuple[str, ...]
    decl: tuple[str, ...]
    packages: tuple[str, ...]
    legs: str


def _strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(x, str) and x for x in value)


def parse(text: str) -> tuple[list[LaneDecl], list[str]]:
    """The entries of a declaration and the schema findings (see the docstring). An entry with a
    finding is left out of the list, so a reader never acts on a half-read entry."""
    try:
        doc = read_decl_toml(text)
    except ValueError as err:
        return [], [f"FIELD {DECL_PATH}: not a declaration this reader knows: {err}"]
    findings: list[str] = []
    if doc.get("schema") != SCHEMA:
        findings.append(f"FIELD {DECL_PATH}: schema is {doc.get('schema')!r}, want {SCHEMA!r}")
    extra = sorted(set(doc) - {"schema", "lane"})
    if extra:
        findings.append(f"FIELD {DECL_PATH}: unknown top-level key(s) {', '.join(extra)}")
    raw = doc.get("lane", [])
    if not isinstance(raw, list) or not raw:
        findings.append(f"FIELD {DECL_PATH}: no [[lane]] entry")
        return [], findings
    out: list[LaneDecl] = []
    seen: dict[str, int] = {}
    for n, entry in enumerate(raw, 1):
        lane = entry.get("id") if isinstance(entry.get("id"), str) else f"#{n}"
        bad: list[str] = []
        unknown = sorted(set(entry) - set(_KEYS))
        if unknown:
            bad.append(f"unknown key(s) {', '.join(unknown)}")
        if not isinstance(entry.get("id"), str) or not _ID.match(entry["id"]):
            bad.append("`id` must be a dispatch id (letters and digits)")
        if not isinstance(entry.get("fn"), str) or not _FN.match(entry["fn"]):
            bad.append("`fn` must name a `layer_...` function")
        cls = entry.get("class")
        if cls not in CLASSES:
            bad.append(f"`class` is {cls!r}, want one of {', '.join(CLASSES)}")
        reason = entry.get("reason", "")
        if not isinstance(reason, str):
            bad.append("`reason` must be a string")
            reason = ""
        if cls in ("E", "S") and not reason.strip():
            bad.append(f"class {cls} needs a `reason`: what the verdict depends on that the key lacks")
        if cls == "D" and reason:
            bad.append("class D carries no `reason`: a D verdict depends on the key alone")
        nondet = entry.get("nondet", [])
        if not _strings(nondet) and nondet != []:
            bad.append("`nondet` must be a list of words")
            nondet = []
        if cls == "S" and not nondet:
            bad.append(f"class S needs `nondet`: one or more of {', '.join(NONDET)}")
        if cls != "S" and nondet:
            bad.append("only class S carries `nondet`")
        strange = [w for w in nondet if w not in NONDET]
        if strange:
            bad.append(f"`nondet` word(s) {', '.join(strange)} not in {', '.join(NONDET)}")
        decl = entry.get("decl", [])
        if not _strings(decl) and decl != []:
            bad.append("`decl` must be a list of globs")
            decl = []
        for pattern in decl:
            try:
                glob_regex(pattern)
            except ValueError as err:
                bad.append(str(err))
        packages = entry.get("packages", [])
        if not _strings(packages) and packages != []:
            bad.append("`packages` must be a list of package names")
            packages = []
        for p in packages:
            if not _PACKAGE.match(p) or p == "*":
                bad.append(f"`packages` entry {p!r} is not <name>, <ws>:<name> or <ws>:*")
        legs = entry.get("legs", "")
        if not isinstance(legs, str):
            bad.append("`legs` must be one path")
            legs = ""
        if lane in seen:
            findings.append(f"DUPLICATE {DECL_PATH}: lane {lane} is declared by entries {seen[lane]} and {n}")
            continue
        seen[lane] = n
        if bad:
            findings.extend(f"FIELD {DECL_PATH}: lane {lane}: {b}" for b in bad)
            continue
        out.append(LaneDecl(entry["id"], entry["fn"], cls, reason, tuple(nondet), tuple(decl),
                            tuple(packages), legs))
    return out, findings


def ids(text: str) -> list[str]:
    """The `id` of every `[[lane]]` table, read or not, in order: what an entry claims to declare
    even when a field of it is refused. Empty when the file does not read at all."""
    try:
        doc = read_decl_toml(text)
    except ValueError:
        return []
    raw = doc.get("lane", [])
    if not isinstance(raw, list):
        return []
    return [e["id"] for e in raw if isinstance(e.get("id"), str)]


def canonical(entry: LaneDecl) -> dict:
    """The entry as a lane's key holds it: every field, defaults written out."""
    return {
        "id": entry.id,
        "fn": entry.fn,
        "class": entry.cls,
        "reason": entry.reason,
        "nondet": list(entry.nondet),
        "decl": list(entry.decl),
        "packages": list(entry.packages),
        "legs": entry.legs,
    }


def split_package(spec: str) -> tuple[str | None, str]:
    """`<ws>:<name>` as (ws, name); a bare name as (None, name)."""
    m = _PACKAGE.match(spec)
    if m is None:
        raise ValueError(f"{spec!r} is not <name>, <ws>:<name> or <ws>:*")
    return m.group("ws"), m.group("name")


def leg_packages(text: str) -> list[str]:
    """The package of every row of a `LEGS=( ... )` table, in order; ValueError when there is no
    table or a row has fewer than three fields. The rows are joined across backslash-newlines as
    bash joins them, and read as `nondefault_feature_legs_gate.legs` reads them."""
    m = re.search(r"(?m)^LEGS=\($(.*?)^\)$", text, re.S)
    if m is None:
        raise ValueError("no `LEGS=( ... )` table")
    out: list[str] = []
    for line in re.sub(r"\\\n", "", m.group(1)).splitlines():
        row = line.strip()
        if not row.startswith('"'):
            continue
        fields = row[1 : row.rindex('"')].split("|")
        if len(fields) < 3 or not fields[0]:
            raise ValueError(f"a LEGS row of fewer than three fields: {row}")
        out.append(fields[0])
    return out


def selftest() -> int:
    cases = 0

    def expect(name: str, ok: bool, detail: object = "") -> None:
        nonlocal cases
        if not ok:
            raise AssertionError(f"lane_decl selftest: {name} FAILED {detail}")
        cases += 1

    good = (
        'schema = "wz-lanes/1"\n\n'
        '[[lane]]\nid = "C1"\nfn = "layer_c1_x"\nclass = "D"\npackages = ["crates:*"]\n\n'
        '[[lane]]\nid = "E"\nfn = "layer_e_y"\nclass = "E"\nreason = "zenohd of the machine"\n'
        'decl = ["deploy/**"]\nlegs = "scripts/lib/t.sh"\n\n'
        '[[lane]]\nid = "M"\nfn = "layer_m_z"\nclass = "S"\nreason = "multicast"\nnondet = ["interfaces"]\n'
    )
    entries, findings = parse(good)
    expect("a well-formed declaration reads whole", findings == [] and [e.id for e in entries] == ["C1", "E", "M"], findings)
    expect("defaults are written out", canonical(entries[0])["decl"] == [] and canonical(entries[2])["nondet"] == ["interfaces"])
    # Each case names the change that turns it red: the rule in `parse` it exercises.
    for broken, word, what in (
        (good.replace('class = "D"', 'class = "X"'), "FIELD", "the class vocabulary check"),
        (good.replace('reason = "zenohd of the machine"\n', ''), "FIELD", "E requires a reason"),
        (good.replace('class = "D"\n', 'class = "D"\nreason = "r"\n'), "FIELD", "D refuses a reason"),
        (good.replace('nondet = ["interfaces"]\n', ''), "FIELD", "S requires nondet"),
        (good.replace('"interfaces"', '"weather"'), "FIELD", "the nondet vocabulary check"),
        (good.replace('class = "D"\n', 'class = "D"\nnondet = ["cores"]\n'), "FIELD", "only S carries nondet"),
        (good.replace('packages = ["crates:*"]', 'packages = ["*"]'), "FIELD", "a bare * names no workspace"),
        (good.replace('decl = ["deploy/**"]', 'decl = ["/abs/**"]'), "FIELD", "a glob must be relative"),
        (good.replace('fn = "layer_c1_x"\n', 'fn = "layer_c1_x"\nowner = "me"\n'), "FIELD", "unknown keys are refused"),
        (good.replace('id = "E"', 'id = "C1"'), "DUPLICATE", "an id declared twice"),
        (good.replace('"wz-lanes/1"', '"wz-lanes/0"'), "FIELD", "the schema word"),
    ):
        got, found = parse(broken)
        expect(f"refused: {what}", any(f.startswith(word) for f in found), found)
    expect("an entry with a finding is left out", [e.id for e in parse(good.replace('class = "D"', 'class = "X"'))[0]] == ["E", "M"])
    legs = 'x\nLEGS=(\n    # a comment\n    "wz-a|hook|f1,\\\n        f2|filt"\n    "wz-b|lane||"\n)\n'
    expect("a LEGS table's rows are read across continuations", leg_packages(legs) == ["wz-a", "wz-b"], leg_packages(legs))
    for bad in ('LEGS=(\n    "wz-a|hook"\n)\n', "no table\n"):
        try:
            leg_packages(bad)
        except ValueError:
            cases += 1
        else:
            raise AssertionError(f"lane_decl selftest: LEGS text {bad!r} was read")
    expect("ids lists an entry a finding left out", ids(good.replace('class = "D"', 'class = "X"')) == ["C1", "E", "M"])
    expect("a package spec splits at its workspace", split_package("deploy/x:wz-y") == ("deploy/x", "wz-y") and split_package("wz-y") == (None, "wz-y"))
    print(f"lane_decl selftest: {cases} cases pass")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    print("usage: lane_decl.py --selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
