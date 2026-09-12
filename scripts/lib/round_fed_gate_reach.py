#!/usr/bin/env python3
"""A gate fed by what a ROUND changes must run where the round happens.

R2576 (no register item) — the citation is `no register item` for the reason
`bump_sweep.py` gives for its own: the class this gate closes is recorded in the
operator's agent-memory register, which has no store `debt-` id for
`gate_provenance_lint` to resolve. Naming it in prose here and `no register
item` in the citation is the honest pair.

## The defect, measured three times in six rounds

A round in this workspace changes the tracked tree, and the gates of this
workspace read the tracked tree. When such a gate runs ONLY in hosted CI, the
commit that moves its subject cannot see what it moved -- and there is nothing
for a careful reader to notice either, because the file holding the pin is not
the file the commit touched.

* R2572 took `switchboard` PARTIAL -> COMPLETE. `depth_axis_census.py` grades
  the PARTIAL corpus against pinned counts; two of them moved and neither pin
  did. Hosted Layer C0 is fail-fast and had already died at 14s on an unrelated
  python-floor lint, so the census did not run there either. The red surfaced
  two rounds later.
* R2575 added `netns-topology.sh` with no provenance citation in its header.
  `gate_provenance_lint.py` says so in one line and costs 0.13s, and it too ran
  only hosted. R2576 found it by running that lint by hand while building THIS
  gate -- which is the argument for the gate, not against it.
* R2576 added an interop witness whose header states a dependency in prose.
  `prose_dep_graph_gate.py` costs 0.73s and could not fix the sentence's
  subject, so it refused the site. THIS GATE WAS ALREADY STANDING AND SAID
  NOTHING: its seed rules named two corpora, and the corpus that red was the
  third. Two hosted runs died on it before R2578 read them.

## The population is DERIVED, by two seed rules and a closure

The third instance is the argument for the rule below. R2576 wrote the seeds
as "the store, and the gate corpus under `scripts/`", which is a list of the
two subjects the two instances it had in hand happened to share -- not the
class. The class is one sentence: A GATE IS ROUND-FED WHEN IT ENUMERATES
TRACKED FILES, because tracked files are what a round changes.

A module is a SEED when its AST shows it doing one of:

1. naming the atomic store file in a string constant. It is one file rather
   than a corpus, and it earns its own rule because nearly every round mutates
   it; or
2. enumerating the tracked corpus -- either by invoking `git ls-files`, which
   IS the repository's own enumerator of exactly that set, or by a
   `glob`/`rglob` under a string constant whose first path segment is a
   TRACKED TOP-LEVEL DIRECTORY.

That directory set is read from `git ls-files` on every run and never written
down here. A hand-written list would need re-typing the first time the tree
grows a directory, and the round that grew it is precisely the round with no
reason to look -- which is this gate's own subject pointed at itself.

The population is then the transitive closure of the seeds under `imports a
sibling module`. The closure is load-bearing, not decoration:
`upstream_release_distance.py` names the store nowhere and reaches it by
importing `gate_reason_claims`, so a seeds-only rule would have reported a
clean surface over a gate it never looked at.

Reading the AST rather than the text is what keeps a mention in a comment out
of the population. On the store rule the two readings agree on all nine seeds
today, which is the control that the AST reading is not the narrower one.

## What the widening cost, MEASURED rather than feared

The rule takes the population from 30 modules to 91 of the 136 under
`scripts/lib`, and that ratio is the finding rather than an alarm: most gates
here read this tree, so most gates here are round-fed. 43 of them already ran
in the hook. 42 more were added to its gate 2z block, which as ONE BLOCK now
costs 68.4-74.8s over six runs against 21.8-28.1s for the twenty R2576 left
it with. Two of the three newly DEFERRED rows below are not deferred for cost
at all -- one needs a BUILT artifact, one answers about the debt queue rather
than about this tree -- and saying so is the point of writing a reason down.

That total is inside the hook's policy rather than a step away from it:
`CLAUDE.md` reserves hosted CI for the feature-subset matrix, C2 clippy,
Layers B/B2 codegen, F/G/Q/Z footprint / cross-compile / interop and every
non-default combination. Not one of those is a static read of files the push
has already written, which is all this block does.

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
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LIB_REL = "scripts/lib"
HOOK_REL = ".githooks/pre-push"

#: Seed rule 1 -- the SSOT. A module naming this string is reading the store.
STORE_PATH = "docs/.atomic/workspace.atomic.json"

#: Seed rule 2a -- the repository's own enumerator of the tracked set. A module
#: that shells to it is asking exactly the question "what does this tree hold".
LS_FILES = "ls-files"

#: module -> why the fast local hook does not run it. MEASURED on this tree at
#: R2576 and R2578, warm, each figure the gate's own wall clock rather than an
#: estimate. A row is not an exemption: every one is PRINTED on every run, a
#: row whose module has left the population is a finding, and so is a row the
#: hook turns out to run.
DEFERRED: dict[str, str] = {
    "verdict_leg_mutation.py": (
        "565.63s, more than SEVEN TIMES what the hook's whole 62-member block "
        "costs (68.4-74.8s over six runs), and it MUTATES the working tree -- "
        "it damages "
        "each verdict leg in place to prove the leg reds. A gate that edits "
        "tracked files cannot run inside a push, where what is being sent has "
        "already been resolved and an interrupt would leave the damage "
        "behind. Hosted Layer C0 owns it."
    ),
    "capi_c_abi_pin.py": (
        "its subject is the BUILT `libwz_capi_c.so`, one per cargo profile, "
        "and it refuses to grade without them (0.04s to say so). The hook "
        "builds neither, so wiring it here would either red every push or "
        "grade whatever stale artifact `crates/target` happened to hold -- the "
        "exact failure `binary_freshness_lint.py` exists to count."
    ),
    "debt_plane_census.py": (
        "exit 3 is its NORMAL state whenever a debt claim stands, which is a "
        "fact about the register's queue and not about the tree this push "
        "sends. A push blocked on the contents of the debt queue would be a "
        "verdict on the wrong subject; 0.35s is not what keeps it out."
    ),
    "prose_named_identifier_gate.py": (
        "16.49s in --check mode. R2576 recorded that as twice the whole rest "
        "of this population; R2578's widening retired that comparison rather "
        "than leaving it to rot, and the figure it is now worth is that one "
        "member would add more than a fifth to a 62-member block costing "
        "68.4-74.8s. Hosted Layer C0 runs it; the hook's budget is why this "
        "does not."
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


def tracked_dirs(root: Path) -> set[str]:
    """Top-level directories `git ls-files` reports, derived on every run.

    Seed rule 2b's corpus. Written down nowhere: see the module doc for why a
    list of these would rot in exactly the round that had no reason to read it.
    """
    out = subprocess.run(
        ["git", LS_FILES],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return {p.split("/")[0] for p in out.stdout.split("\n") if "/" in p}


def round_fed(sources: dict[str, str], corpus_dirs: set[str]) -> set[str]:
    """Modules a round's own changes feed: the seeds, plus whatever imports them.

    Pure over `sources` and `corpus_dirs`, so the selftest drives both the rule
    and the closure -- the two halves most able to narrow silently.
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
                if node.value == LS_FILES:
                    # Seed rule 2a. The enumerator itself, so no glob is wanted.
                    seeds.add(name)
                if node.value.strip("/").split("/")[0] in corpus_dirs:
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


#: A bash array whose name ends `_gates`, opened on its own line. The ONLY
#: place a bare filename counts as an invocation -- see `hook_invocations`.
GATE_LIST_OPEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*_gates=\(\s*$")
#: One quoted member of such a list: a bare module name, optional arguments.
GATE_LIST_MEMBER = re.compile(r'"([A-Za-z0-9_.-]+\.py)(?:\s[^"]*)?"\s*$')


def hook_invocations(hook_src: str) -> set[str]:
    """Which scripts/lib modules the pre-push hook names.

    TWO forms, because the hook legitimately uses both and forcing one shape on
    it would be this gate dictating rather than reading.

    Most gates spell the path on their own invocation line
    (`python3 scripts/lib/x.py`). Gate 2z runs a LIST, and that list holds BARE
    names with the prefix on the invocation instead -- which is not cosmetic:
    `hook_gate_boundary_gate.py` grades a section by matching
    `(python3|bash)\\s+scripts/` against its code, so a loop expanding a full
    path out of an array reads to that gate as a section that runs NOTHING.
    MEASURED rather than supposed: R2576 shipped the array form and hosted
    Layer C0 refused the next push, naming `gate 2z`.

    The bare form is read ONLY from inside a `*_gates=( ... )` array, so a
    quoted filename anywhere else in the hook cannot pass for an invocation.
    """
    out: set[str] = set()
    marker = LIB_REL + "/"
    in_list = False
    for line in hook_src.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if GATE_LIST_OPEN.match(stripped):
            in_list = True
            continue
        if in_list:
            if stripped.startswith(")"):
                in_list = False
            else:
                member = GATE_LIST_MEMBER.match(stripped)
                if member:
                    out.add(member.group(1))
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
            "the tracked corpus. The derivation found nothing to grade, which "
            "reads exactly like a clean surface and is not one -- a round in "
            "this workspace changes those subjects nearly every time."
        )
        return out, 0

    for name in sorted(population):
        if name in invoked or name in deferred:
            continue
        out.append(
            f"`{name}` is fed by what a round changes -- the atomic store or "
            f"the tracked corpus -- and the pre-push hook does not run it, so "
            f"the commit that moves its subject cannot see what it moved. Run "
            f"it in the hook, or add a DEFERRED row saying what that costs."
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
    corpus_dirs = tracked_dirs(root)
    if not corpus_dirs:
        # Seed rule 2b's input, and an empty one silently narrows the rule to
        # 2a. A derivation whose own input went missing does not report green.
        print(
            "round-fed-gate-reach: FAIL -- `git ls-files` named no tracked "
            "directory, so seed rule 2b graded nothing and the population "
            "below is narrower than the rule by an amount nobody measured.",
            file=sys.stderr,
        )
        return 1
    population = round_fed(sources, corpus_dirs)
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
    # The fixture's tracked-directory set, standing in for `git ls-files`. It
    # deliberately does NOT hold every directory this tree has: an arm below
    # asks what happens to a glob under a name the set does not carry.
    dirs = {"scripts", "crates", "docs"}

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
            "`git ls-files` alone is a seed -- it IS the enumerator",
            {"a.py": 'subprocess.run(["git", "ls-files"])\n'},
            {"a.py"},
        ),
        (
            "`ls-files` in a COMMENT is not, same as the store rule",
            {"a.py": "# git ls-files\nX = 1\n"},
            set(),
        ),
        (
            "a glob under ANOTHER tracked tree is a seed -- R2578's miss",
            {"a.py": 'D = "crates"\nfor p in D.rglob("*.rs"):\n    pass\n'},
            {"a.py"},
        ),
        (
            "a glob under a tracked SUBTREE is a seed -- its subject is narrower, not absent",
            {"a.py": 'D = "crates/wz-capture/src"\nfor p in D.glob("*.rs"):\n    pass\n'},
            {"a.py"},
        ),
        (
            "a glob under a name the tree does not track is NOT",
            {"a.py": 'D = "target/debug"\nfor p in D.glob("*.rs"):\n    pass\n'},
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
        got = round_fed(sources, dirs)
        ok = got == want
        print(f"  [{'ok' if ok else 'FAIL'}] closure -- {name}: {sorted(got)}")
        if not ok:
            failed += 1

    # The corpus rule with an EMPTY directory set narrows to rule 2a in
    # silence, which is why `run` refuses to grade with one. Pinned here so the
    # refusal cannot be deleted as redundant.
    starved = round_fed({"a.py": corpus_seed}, set())
    ok = starved == set()
    print(
        f"  [{'ok' if ok else 'FAIL'}] closure -- an EMPTY tracked-dir set "
        f"silently drops a corpus seed, which is why `run` refuses it: {sorted(starved)}"
    )
    if not ok:
        failed += 1

    hook_cases: list[tuple[str, str, set[str]]] = [
        ("an invocation is read", "if ! python3 scripts/lib/a_gate.py; then\n", {"a_gate.py"}),
        ("arguments do not hide the name", "python3 scripts/lib/a_gate.py --check\n", {"a_gate.py"}),
        ("a COMMENTED invocation does not count", "# python3 scripts/lib/a_gate.py\n", set()),
        ("two on one line are both read", "x=scripts/lib/a.py; y=scripts/lib/b.py\n", {"a.py", "b.py"}),
        (
            "a BARE name inside a `*_gates=(` list is an invocation",
            'round_fed_gates=(\n    "a.py"\n    "b.py --check"\n)\n',
            {"a.py", "b.py"},
        ),
        ("the same bare name OUTSIDE such a list is not", 'echo "a.py"\n', set()),
        (
            "the list ends at its closing paren",
            'x_gates=(\n    "a.py"\n)\necho "b.py"\n',
            {"a.py"},
        ),
        ("an array that is not a gate list opens nothing", 'other=(\n    "a.py"\n)\n', set()),
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

    # +1 for the starved-directory-set arm, which is not in a case table
    # because its input is the one the tables hold fixed.
    total = len(closure_cases) + len(hook_cases) + len(rule_cases) + 1
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
