#!/usr/bin/env python3
"""A gate whose OWN source a push changes must pass its OWN selftest there.

R2582 (no register item) — the citation is `no register item` for the reason
`round_fed_gate_reach.py` gives for its own: the class this closes is recorded
in the operator's agent-memory register, which has no store `debt-` id for
`gate_provenance_lint` to resolve.

## The defect, measured

R2577 edited `upstream_citation_anchor_gate.py`, writing two upstream path
literals into a budget comment. That gate's `--selftest` refuses its own
source carrying an upstream path literal, and hosted Layer C0 runs the selftest
with `|| return 1` -- so the layer died on it at 259s for FIVE pushes, R2577
through R2582, while every local gate stayed green. The pre-push hook ran that
gate's `--check` (gate 2f) and never its `--selftest`.

The general shape: a gate's selftest validates the GATE's own logic, which only
changes when the gate's source changes. Running every selftest on every push
would pay for 80-odd suites to check files nobody touched; running NONE of them
locally means a commit can break a gate's self-consistency and learn of it from
a hosted run five rounds later. The right population is exactly the gates the
push itself edits.

## The population is DERIVED, and the tighter-looking rule was the wrong one

A module is a member when the push changes it AND `--selftest` occurs in it as
a string CONSTANT in code (AST, so a mention in a comment is not a member).

MEASURED before this was written, over all 136 modules under `scripts/lib`: 81
carry the constant, 0 carry it only in text. A TIGHTER rule was tried first --
"accepts it via `add_argument('--selftest')` or a `== '--selftest'` compare" --
and it matched 77. The four it dropped (`binary_freshness_lint.py`,
`hook_script_reference_gate.py`, `hosted_pending_kind.py`,
`prose_build_closure_gate.py`) were then RUN with `--selftest` and all four
accepted it and passed. So the stricter rule would have silently skipped real
selftests: it encoded the dispatch shapes its author thought of, and missed the
ones he did not. The looser rule's only possible error is a module that names
the constant without accepting it, and that fails LOUDLY here as an unknown
argument -- the safe direction for a gate to be wrong in.

## What this does not do

It runs selftests only. A gate's `--check` against the tree is the business of
whichever hook gate already invokes it; this adds nothing there, and a changed
gate with no `--selftest` arm is simply not a member.
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LIB_PREFIX = "scripts/lib/"
SELFTEST = "--selftest"


def carries_selftest_constant(source: str) -> bool:
    """True when `--selftest` is a string constant somewhere in the code."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # A gate that does not parse cannot be skipped: its selftest is run and
        # fails, which is the loud answer a broken gate file deserves.
        return True
    return any(isinstance(node, ast.Constant) and node.value == SELFTEST for node in ast.walk(tree))


def members(changed: list[str], read) -> list[str]:
    """Changed paths that are gate modules carrying a selftest arm.

    Pure over `changed` and `read` (path -> source or None), so the selftest
    drives the rule without a repository.
    """
    out = []
    for rel in changed:
        if not rel.startswith(LIB_PREFIX) or not rel.endswith(".py"):
            continue
        if "/" in rel[len(LIB_PREFIX) :]:
            continue
        source = read(rel)
        if source is None:
            # Deleted or renamed away in this push: nothing left to test.
            continue
        if carries_selftest_constant(source):
            out.append(rel)
    return sorted(out)


def changed_paths(diff_range: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", diff_range],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"changed-gate-selftests: git diff {diff_range} failed "
            f"(rc={result.returncode}): {result.stderr.strip()}"
        )
    return [line for line in result.stdout.split("\n") if line]


def read_tracked(rel: str) -> str | None:
    path = REPO_ROOT / rel
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def run(diff_range: str) -> int:
    population = members(changed_paths(diff_range), read_tracked)
    if not population:
        print(f"changed-gate-selftests: no gate module with a selftest arm changed in {diff_range}")
        return 0
    failed = []
    for rel in population:
        result = subprocess.run(
            [sys.executable, rel, SELFTEST],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        verdict = "ok" if result.returncode == 0 else f"FAIL rc={result.returncode}"
        print(f"  {verdict:10s} {rel} {SELFTEST}")
        if result.returncode != 0:
            failed.append((rel, result.stdout + result.stderr))
    print(
        f"changed-gate-selftests: {len(population)} changed gate(s) with a selftest arm, "
        f"{len(failed)} failed"
    )
    for rel, output in failed:
        tail = "\n".join(output.strip().split("\n")[-8:])
        print(f"--- {rel} ---\n{tail}", file=sys.stderr)
    return 1 if failed else 0


def selftest() -> int:
    sources = {
        "scripts/lib/argparse_gate.py": 'p.add_argument("--selftest")\n',
        "scripts/lib/compare_gate.py": 'if sys.argv[1:] == ["--selftest"]:\n    pass\n',
        "scripts/lib/comment_only.py": "# run with --selftest\nX = 1\n",
        "scripts/lib/no_arm.py": "X = 1\n",
        "scripts/lib/broken.py": "def (\n",
        "scripts/lib/nested/deep.py": 'p.add_argument("--selftest")\n',
        "crates/wz/src/lib.rs": '"--selftest"\n',
    }
    read = sources.get
    cases = [
        ("an argparse arm is a member", ["scripts/lib/argparse_gate.py"], ["scripts/lib/argparse_gate.py"]),
        (
            "a hand-rolled compare arm is a member -- the shape the tighter rule MISSED",
            ["scripts/lib/compare_gate.py"],
            ["scripts/lib/compare_gate.py"],
        ),
        ("a mention in a COMMENT is not a member", ["scripts/lib/comment_only.py"], []),
        ("a gate with no selftest arm is not a member", ["scripts/lib/no_arm.py"], []),
        (
            "a gate that does not PARSE is a member, so its failure is loud",
            ["scripts/lib/broken.py"],
            ["scripts/lib/broken.py"],
        ),
        ("a file outside scripts/lib is not a member", ["crates/wz/src/lib.rs"], []),
        ("a nested path under scripts/lib is not a member", ["scripts/lib/nested/deep.py"], []),
        ("a path the push DELETED is not a member", ["scripts/lib/gone.py"], []),
        (
            "the population is exactly the changed members, sorted",
            ["scripts/lib/no_arm.py", "scripts/lib/compare_gate.py", "scripts/lib/argparse_gate.py"],
            ["scripts/lib/argparse_gate.py", "scripts/lib/compare_gate.py"],
        ),
    ]
    failed = 0
    for name, changed, want in cases:
        got = members(changed, read)
        ok = got == want
        print(f"  [{'ok' if ok else 'FAIL'}] {name}: {got}")
        failed += 0 if ok else 1
    if failed:
        print(f"changed-gate-selftests selftest: {failed} of {len(cases)} arm(s) FAILED")
        return 1
    print(f"changed-gate-selftests selftest: {len(cases)}/{len(cases)} arm(s) pass")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--selftest", action="store_true", help="drive the membership rule")
    parser.add_argument("--range", dest="diff_range", help="the push's diff range, A..B")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if not args.diff_range:
        parser.error("--range A..B is required unless --selftest")
    return run(args.diff_range)


if __name__ == "__main__":
    raise SystemExit(main())
