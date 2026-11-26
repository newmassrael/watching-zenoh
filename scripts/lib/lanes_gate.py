#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4654 (no register item) -- the lane declaration held to the dispatch table it declares.

RFC 0001 (`docs/rfc/0001-a-lane-lands-alone-and-a-verdict-is-keyed-by-what-it-read.md`,
section 5.4, stage M1): every lane of `scripts/run-ci.sh` has one entry in `scripts/lib/lanes.toml`,
and the entry says what the dispatch line and the lane's hosted job say, the way `soft_job_gate.py`
holds `deploy/soft_jobs.json` to the workflows. A lane with no entry would have no class and no
declared inputs, and a lane's key would silently lose what its entry adds; an entry with no lane is a
declaration nothing reads. Findings, each a word the reader can grep:

  UNDECLARED  a dispatch line `run_layer <id> <fn>` with no entry
  ORPHAN      an entry whose id no dispatch line has
  DUPLICATE   an id declared by two entries
  FIELD       an entry breaks the schema (`lane_decl.py`), names another function than its
              dispatch line, declares a glob no tracked path matches, a package no workspace has,
              a leg table that is missing or names such a package, or is class D while its hosted
              job provisions something before it or the lane asks the machine for a program or a
              package (`runci_plan.py`'s requirements): such a verdict depends on the machine, which
              a D key does not hold (RFC 0001 5.5)

It reads the checkout (the index's paths, the files on disk), so it judges what a commit would
carry. It prints the lanes by class; how many of them are opaque is `lane_digest.py --check`'s.

  python3 scripts/lib/lanes_gate.py --check
  python3 scripts/lib/lanes_gate.py --selftest
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lane_decl  # noqa: E402
import lane_graph  # noqa: E402
import runci_plan  # noqa: E402
from git_tree import Fixture, WorkTree  # noqa: E402

RUNCI = "scripts/run-ci.sh"


def findings(runci_text: str, decl_text: str, tree, hosted: dict[str, runci_plan.Hosted],
             asks: dict[str, runci_plan.Asks]) -> list[str]:
    """Every finding of the declaration against the dispatch table, the tree, the hosted jobs and
    the lanes' requirements (see the module docstring)."""
    out: list[str] = []
    entries, schema = lane_decl.parse(decl_text)
    out.extend(schema)
    dispatch = {m.group(1): m.group(2) for m in runci_plan.DISPATCH.finditer(runci_text)}
    declared = set(lane_decl.ids(decl_text))
    for lane in dispatch:
        if lane not in declared:
            out.append(f"UNDECLARED lane {lane} ({dispatch[lane]}) has no entry in {lane_decl.DECL_PATH}")
    for lane in sorted(declared - set(dispatch)):
        out.append(f"ORPHAN {lane_decl.DECL_PATH}: lane {lane} is in no dispatch line of {RUNCI}")
    spaces = lane_graph.workspaces(tree)
    for e in entries:
        where = f"FIELD {lane_decl.DECL_PATH}: lane {e.id}"
        if e.id in dispatch and dispatch[e.id] != e.fn:
            out.append(f"{where}: fn is {e.fn}, the dispatch line runs {dispatch[e.id]}")
        for pattern in e.decl:
            if not tree.glob(pattern):
                out.append(f"{where}: decl glob {pattern!r} matches no tracked path")
        for spec in e.packages:
            if not lane_graph.resolve(spaces, spec):
                out.append(f"{where}: package {spec!r} is a local package of no workspace")
        if e.legs:
            text = tree.text(e.legs)
            if text is None:
                out.append(f"{where}: legs {e.legs} is not a tracked file")
            else:
                try:
                    rows = lane_decl.leg_packages(text)
                except ValueError as err:
                    out.append(f"{where}: legs {e.legs}: {err}")
                    rows = []
                for name in sorted(set(rows)):
                    if not lane_graph.resolve(spaces, name):
                        out.append(f"{where}: a row of {e.legs} runs {name}, a local package of no workspace")
        if e.cls == "D" and e.id in dispatch:
            why = []
            h = hosted.get(e.id)
            if h is not None and h.prep:
                why.append("its hosted job provisions " + ", ".join(" ".join(argv) for _, argv in h.prep))
            a = asks.get(e.id)
            if a is not None and (a.needs or a.packages):
                why.append("it asks the machine for " + ", ".join(a.needs + a.packages))
            if why:
                out.append(f"{where}: class D, but {'; and '.join(why)}: the verdict depends on the machine (E)")
    return out


def _hosted(tree) -> dict[str, runci_plan.Hosted]:
    import yaml  # the planner reads the workflows with PyYAML too

    docs = [yaml.safe_load(tree.text(str(p)) or "") or {} for p in runci_plan.HOSTED_WORKFLOWS
            if tree.text(str(p)) is not None]
    return runci_plan.hosted_runs(docs)


def check(root: Path) -> int:
    tree = WorkTree(root)
    runci_text = tree.text(RUNCI)
    decl_text = tree.text(lane_decl.DECL_PATH)
    if runci_text is None or decl_text is None:
        print(f"lanes_gate: FAIL -- {RUNCI} or {lane_decl.DECL_PATH} is not a tracked file", file=sys.stderr)
        return 1
    asks = runci_plan.lane_asks(runci_text, runci_plan.lane_commands(), runci_plan.LANE_PACKAGES)
    found = findings(runci_text, decl_text, tree, _hosted(tree), asks)
    for f in found:
        print(f"lanes_gate: {f}", file=sys.stderr)
    if found:
        print(f"lanes_gate: FAIL -- {len(found)} finding(s)", file=sys.stderr)
        return 1
    entries, _ = lane_decl.parse(decl_text)
    by = {c: sum(1 for e in entries if e.cls == c) for c in lane_decl.CLASSES}
    print(f"lanes_gate: OK -- {len(entries)} lane(s) declared, one per dispatch line: "
          + ", ".join(f"{n} {c}" for c, n in by.items()))
    return 0


# -- the selftest --------------------------------------------------------------------------------

_RUNCI = (
    "layer_a_x() {\n    cargo test -p app\n}\n"
    "layer_b_y() {\n    bash scripts/lib/legs.sh\n}\n"
    "run_layer A layer_a_x || overall=1\n"
    "run_layer B layer_b_y || overall=1\n"
)
_DECL = (
    'schema = "wz-lanes/1"\n\n'
    '[[lane]]\nid = "A"\nfn = "layer_a_x"\nclass = "D"\ndecl = ["docs/**"]\npackages = ["crates:app"]\n\n'
    '[[lane]]\nid = "B"\nfn = "layer_b_y"\nclass = "E"\nreason = "an oracle"\nlegs = "scripts/lib/legs.sh"\n'
)
_LEGS = 'LEGS=(\n    "app|hook||"\n    "core|lane|x|"\n)\n'


def selftest() -> int:
    cases = 0

    def expect(name: str, ok: bool, detail: object = "") -> None:
        nonlocal cases
        if not ok:
            raise AssertionError(f"lanes_gate selftest: {name} FAILED {detail}")
        cases += 1

    with Fixture() as fx:
        fx.commit({**lane_graph.FIXTURE, "scripts/lib/legs.sh": _LEGS, "docs/x.md": "x\n"}, lane_graph.FIXTURE_LINKS)
        tree = WorkTree(fx.root)
        quiet: dict[str, runci_plan.Hosted] = {"A": runci_plan.Hosted({}), "B": runci_plan.Hosted({})}
        none: dict[str, runci_plan.Asks] = {}
        clean = findings(_RUNCI, _DECL, tree, quiet, none)
        expect("a declaration that agrees with everything has no finding", clean == [], clean)
        # Each case: the declaration, table or job broken one way, the word expected, and the
        # rule of `findings` whose removal turns the case red.
        for runci, decl, hosted, asks, word, rule in (
            (_RUNCI + "run_layer C layer_a_x || overall=1\n", _DECL, quiet, none, "UNDECLARED", "a dispatch id with no entry"),
            (_RUNCI, _DECL + '\n[[lane]]\nid = "Z"\nfn = "layer_z"\nclass = "D"\n', quiet, none, "ORPHAN", "an entry with no dispatch line"),
            (_RUNCI, _DECL + '\n[[lane]]\nid = "A"\nfn = "layer_a_x"\nclass = "D"\n', quiet, none, "DUPLICATE", "an id twice"),
            (_RUNCI, _DECL.replace('fn = "layer_a_x"', 'fn = "layer_a_other"'), quiet, none, "FIELD", "fn against the dispatch line"),
            (_RUNCI, _DECL.replace('class = "D"', 'class = "Q"'), quiet, none, "FIELD", "the schema"),
            (_RUNCI, _DECL.replace('"docs/**"', '"nowhere/**"'), quiet, none, "FIELD", "a glob that matches nothing"),
            (_RUNCI, _DECL.replace('"crates:app"', '"crates:ghost"'), quiet, none, "FIELD", "a package no workspace has"),
            (_RUNCI, _DECL.replace('legs = "scripts/lib/legs.sh"', 'legs = "scripts/lib/gone.sh"'), quiet, none, "FIELD", "a leg table that is not tracked"),
            (_RUNCI, _DECL.replace('legs = "scripts/lib/legs.sh"', 'legs = "docs/x.md"'), quiet, none, "FIELD", "a leg file with no LEGS table"),
            (_RUNCI, _DECL, {"A": runci_plan.Hosted({}, [({}, ["scripts/build-zenohd.sh"])]), "B": runci_plan.Hosted({})}, none, "FIELD", "class D under a provisioning job"),
            (_RUNCI, _DECL, quiet, {"A": runci_plan.Asks(["qemu-system-arm"])}, "FIELD", "class D asking for a program"),
        ):
            got = findings(runci, decl, tree, hosted, asks)
            expect(f"refused: {rule}", any(f.startswith(word) for f in got), got)
        ghost = _LEGS.replace('"core|lane|x|"', '"ghost|lane|x|"')
        (fx.root / "scripts" / "lib" / "legs.sh").write_text(ghost, encoding="utf-8")
        got = findings(_RUNCI, _DECL, WorkTree(fx.root), quiet, none)
        # Red if the rows of a leg table are not resolved against the workspaces.
        expect("refused: a leg row naming a package no workspace has", any("ghost" in f for f in got), got)
        # The checkout is read from disk, so the clean leg table goes back before the next case.
        (fx.root / "scripts" / "lib" / "legs.sh").write_text(_LEGS, encoding="utf-8")
        e_asks = findings(_RUNCI, _DECL, WorkTree(fx.root), quiet, {"B": runci_plan.Asks(["zenohd"])})
        # Red if the class-D machine rule is applied to an E lane too.
        expect("an E lane may ask the machine", e_asks == [], e_asks)
    print(f"lanes_gate selftest: {cases} cases pass")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["--check"]:
        return check(Path(__file__).resolve().parents[2])
    print("usage: lanes_gate.py --check | --selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
