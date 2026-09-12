#!/usr/bin/env python3
"""A gate fed by what a ROUND changes must run where the round happens.

R2576 (no register item) — the citation is `no register item` for the reason
`bump_sweep.py` gives for its own: the class this gate closes is recorded in the
operator's agent-memory register, which has no store `debt-` id for
`gate_provenance_lint` to resolve. Naming it in prose here and `no register
item` in the citation is the honest pair.

## The defect, measured twice in four rounds

A round in this workspace changes two things almost every time: the atomic
store (it closes or re-grades an atom) and the gate corpus under `scripts/`
(it writes the instrument that made the round's claim checkable). Gates read
both. When such a gate runs ONLY in hosted CI, the commit that moves its
subject cannot see what it moved -- and there is nothing for a careful reader
to notice either, because the file holding the pin is not the file the commit
touched.

* R2572 took `switchboard` PARTIAL -> COMPLETE. `depth_axis_census.py` grades
  the PARTIAL corpus against pinned counts; two of them moved and neither pin
  did. Hosted Layer C0 is fail-fast and had already died at 14s on an unrelated
  python-floor lint, so the census did not run there either. The red surfaced
  two rounds later.
* R2575 added `netns-topology.sh` with no provenance citation in its header.
  `gate_provenance_lint.py` says so in one line and costs 0.13s, and it too ran
  only hosted. R2576 found it by running that lint by hand while building THIS
  gate -- which is the argument for the gate, not against it.

## The population is DERIVED, by two seed rules and a closure

A module is a SEED when its AST shows it reading one of those two subjects:

1. a string constant naming the atomic store file, or
2. a string constant naming the `scripts` tree TOGETHER with a `glob`/`rglob`
   call -- that is, it enumerates the gate corpus rather than opening one file.

The population is then the transitive closure of the seeds under `imports a
sibling module`. The closure is load-bearing, not decoration:
`upstream_release_distance.py` names the store nowhere and reaches it by
importing `gate_reason_claims`, so a seeds-only rule would have reported a
clean surface over a gate it never looked at.

Reading the AST rather than the text is what keeps a mention in a comment out
of the population. On the store rule the two readings agree on all nine seeds
today, which is the control that the AST reading is not the narrower one.

## What DEFERRED costs, and why it is not an exemption list

A row must carry a MEASURED reason, and every row is PRINTED on every run, so a
deferral can never read as coverage -- the rule `nondefault-tests-gate.sh`
already applies to its own legs. A row whose module has left the population is
a finding, and so is a row the hook turns out to run: a deferral that has
quietly become false claims a cost nobody is paying.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LIB_REL = "scripts/lib"
HOOK_REL = ".githooks/pre-push"

#: Seed rule 1 -- the SSOT. A module naming this string is reading the store.
STORE_PATH = "docs/.atomic/workspace.atomic.json"

#: Seed rule 2 -- the gate corpus. A module naming one of these AND globbing is
#: enumerating the scripts tree, so what a round WRITES there is its subject.
CORPUS_DIRS = frozenset({"scripts", "scripts/lib", "scripts/lib/"})

#: module -> why the fast local hook does not run it. MEASURED on this tree at
#: R2576, warm, each figure the gate's own wall clock rather than an estimate.
DEFERRED: dict[str, str] = {
    "prose_named_identifier_gate.py": (
        "16.49s in --check mode, three times the next slowest member and twice "
        "the whole rest of this population put together. Hosted Layer C0 runs "
        "it; the hook's budget is the reason it does not."
    ),
    "upstream_release_distance.py": (
        "queries the GitHub releases API (8.31s, network-bound). A gate that "
        "needs the network cannot be a verdict on a developer's machine -- "
        "offline it would red a push for a reason the push did not cause. "
        "Hosted Layer U owns it."
    ),
    "bump_sweep.py": (
        "18.47s in --check mode, and it is an AGGREGATE: it sweeps a pin "
        "bump's whole re-measurement surface, most of whose members this hook "
        "already grades one by one. Running it here would pay that population "
        "twice and report it in a shape nobody reads at push time."
    ),
}


def modules(root: Path) -> dict[str, str]:
    """`{filename: source}` for every python gate under scripts/lib."""
    return {p.name: p.read_text() for p in sorted((root / LIB_REL).glob("*.py"))}


def round_fed(sources: dict[str, str]) -> set[str]:
    """Modules a round's own changes feed: the seeds, plus whatever imports them.

    Pure over `sources`, so the selftest drives the closure itself -- the half
    most able to narrow silently.
    """
    seeds: set[str] = set()
    imports: dict[str, set[str]] = {}
    stems = {name[:-3]: name for name in sources if name.endswith(".py")}

    for name, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            # A module that does not parse is not silently dropped: it cannot
            # be read, so it is reported as a seed and the operator looks.
            seeds.add(name)
            imports[name] = set()
            continue
        named: set[str] = set()
        names_corpus = False
        globs = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if STORE_PATH in node.value:
                    seeds.add(name)
                if node.value in CORPUS_DIRS:
                    names_corpus = True
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    named.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    named.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Attribute) and fn.attr in ("glob", "rglob"):
                    globs = True
        if names_corpus and globs:
            seeds.add(name)
        imports[name] = {stems[s] for s in named if s in stems}

    population = set(seeds)
    changed = True
    while changed:
        changed = False
        for name, deps in imports.items():
            if name not in population and deps & population:
                population.add(name)
                changed = True
    return population


def hook_invocations(hook_src: str) -> set[str]:
    """Which scripts/lib modules the pre-push hook names."""
    out: set[str] = set()
    marker = LIB_REL + "/"
    for line in hook_src.split("\n"):
        if line.lstrip().startswith("#"):
            continue
        start = 0
        while True:
            at = line.find(marker, start)
            if at < 0:
                break
            token = ""
            for ch in line[at + len(marker) :]:
                if ch.isalnum() or ch in "_.-":
                    token += ch
                else:
                    break
            if token.endswith(".py"):
                out.add(token)
            start = at + len(marker)
    return out


def findings_from(
    population: set[str], invoked: set[str], deferred: dict[str, str]
) -> tuple[list[str], int]:
    """(findings, population size). Pure: the rule sees three sets, no tree."""
    out: list[str] = []
    if not population:
        out.append(
            "no module under scripts/lib reads the atomic store or enumerates "
            "the gate corpus. The derivation found nothing to grade, which "
            "reads exactly like a clean surface and is not one -- a round in "
            "this workspace changes both of those subjects nearly every time."
        )
        return out, 0

    for name in sorted(population):
        if name in invoked or name in deferred:
            continue
        out.append(
            f"`{name}` is fed by what a round changes -- the atomic store or "
            f"the gate corpus -- and the pre-push hook does not run it, so the "
            f"commit that moves its subject cannot see what it moved. Run it "
            f"in the hook, or add a DEFERRED row saying what that costs."
        )
    for name in sorted(deferred):
        if name not in population:
            out.append(
                f"DEFERRED names `{name}`, which no longer reads either "
                f"subject. A deferral for a gate that has left the population "
                f"is a row nobody will ever re-read: drop it."
            )
        elif name in invoked:
            out.append(
                f"DEFERRED says the hook does not run `{name}` and the hook "
                f"runs it. One of the two is stale, and a false deferral is "
                f"worse than none: it claims a cost that is not being paid."
            )
    return out, len(population)


def report(population: set[str], invoked: set[str], deferred: dict[str, str]) -> None:
    ran = sorted(n for n in population if n in invoked)
    print(
        f"round-fed-gate-reach: {len(population)} gate(s) are fed by what a "
        f"round changes, {len(ran)} run in {HOOK_REL}, {len(deferred)} deferred"
    )
    for name in sorted(deferred):
        print(f"  deferred: {name} -- {deferred[name]}")


def run(root: Path) -> int:
    sources = modules(root)
    population = round_fed(sources)
    invoked = hook_invocations((root / HOOK_REL).read_text())
    findings, size = findings_from(population, invoked, DEFERRED)
    report(population, invoked, DEFERRED)
    if findings:
        print("round-fed-gate-reach: FAIL", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print(f"round-fed-gate-reach: OK -- {size} gate(s) accounted for")
    return 0


def selftest() -> int:
    failed = 0
    store_seed = f'STORE = "{STORE_PATH}"\n'
    corpus_seed = 'D = "scripts/lib"\nfor p in D.glob("*.py"):\n    pass\n'

    closure_cases: list[tuple[str, dict[str, str], set[str]]] = [
        ("a module naming the store is a seed", {"a.py": store_seed}, {"a.py"}),
        (
            "a module naming the store in a COMMENT is not",
            {"a.py": f"# {STORE_PATH}\nX = 1\n"},
            set(),
        ),
        ("a module enumerating the gate corpus is a seed", {"a.py": corpus_seed}, {"a.py"}),
        (
            "naming the corpus WITHOUT globbing is not -- it opens one file",
            {"a.py": 'D = "scripts/lib"\nopen(D)\n'},
            set(),
        ),
        (
            "globbing WITHOUT naming the corpus is not -- it globs elsewhere",
            {"a.py": 'P.glob("*.py")\n'},
            set(),
        ),
        (
            "an importer of a seed is in the population",
            {"a.py": store_seed, "b.py": "import a\n"},
            {"a.py", "b.py"},
        ),
        (
            "the closure is transitive, not one hop",
            {"a.py": store_seed, "b.py": "import a\n", "c.py": "from b import x\n"},
            {"a.py", "b.py", "c.py"},
        ),
        ("an unrelated module stays out", {"a.py": store_seed, "z.py": "import json\n"}, {"a.py"}),
        ("a module that does not parse is reported, never dropped", {"a.py": "def (\n"}, {"a.py"}),
    ]
    for name, sources, want in closure_cases:
        got = round_fed(sources)
        ok = got == want
        print(f"  [{'ok' if ok else 'FAIL'}] closure -- {name}: {sorted(got)}")
        if not ok:
            failed += 1

    hook_cases: list[tuple[str, str, set[str]]] = [
        ("an invocation is read", "if ! python3 scripts/lib/a_gate.py; then\n", {"a_gate.py"}),
        ("arguments do not hide the name", "python3 scripts/lib/a_gate.py --check\n", {"a_gate.py"}),
        ("a COMMENTED invocation does not count", "# python3 scripts/lib/a_gate.py\n", set()),
        ("two on one line are both read", "x=scripts/lib/a.py; y=scripts/lib/b.py\n", {"a.py", "b.py"}),
    ]
    for name, src, want in hook_cases:
        got = hook_invocations(src)
        ok = got == want
        print(f"  [{'ok' if ok else 'FAIL'}] hook -- {name}: {sorted(got)}")
        if not ok:
            failed += 1

    rule_cases: list[tuple[str, set[str], set[str], dict[str, str], int]] = [
        ("every member runs -> clean", {"a.py"}, {"a.py"}, {}, 0),
        ("a member the hook does not run -> the R2572 shape", {"a.py"}, set(), {}, 1),
        ("a member with a deferral -> silent", {"a.py"}, set(), {"a.py": "slow"}, 0),
        ("a deferral outside the population -> stale row", {"a.py"}, {"a.py"}, {"b.py": "slow"}, 1),
        ("a deferral the hook actually runs -> false deferral", {"a.py"}, {"a.py"}, {"a.py": "slow"}, 1),
        ("an EMPTY population FAILS rather than passing", set(), set(), {}, 1),
    ]
    for name, population, invoked, deferred, want in rule_cases:
        got, _size = findings_from(population, invoked, deferred)
        ok = len(got) == want
        print(f"  [{'ok' if ok else 'FAIL'}] rule -- {name}: {len(got)}, want {want}")
        if not ok:
            failed += 1
            for g in got:
                print(f"        {g}")

    total = len(closure_cases) + len(hook_cases) + len(rule_cases)
    if failed:
        print(f"round-fed-gate-reach selftest: {failed} of {total} arm(s) FAILED")
        return 1
    print(f"round-fed-gate-reach selftest: {total}/{total} arm(s) pass")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="a gate fed by what a round changes must run where the round happens"
    )
    parser.add_argument("--selftest", action="store_true", help="drive the rule")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    return run(REPO_ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
