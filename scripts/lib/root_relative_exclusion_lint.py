#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2338 (no register item) - a walk's exclusion must be tested on a path
RELATIVE to the walked root, never on the absolute one.

The citation is `no register item` because this closes a DEFECT found the same
round rather than a listed debt: hosted run 33839814655 died with

    upstream-reads: FAIL -- .../target/zenohd-build/zenoh-src yielded 0 Rust
    file(s), under the floor of 200

about a checkout that was complete. `upstream_reads_the_surface.py` skipped a
build directory inside the upstream tree with `if "target" in path.parts`, and
`path` there is ABSOLUTE. Hosted CI clones the pinned zenoh into
`target/zenohd-build/zenoh-src`, so the ancestor named `target` matched every
file, the walk yielded nothing, and the floor -- correctly -- refused to grade.
`store_reasons_resolve.py` inherited the shape from it and was one layer behind
the same red.

## Why a lint and not two edits

The filter is not wrong at those two files; it is wrong in a WAY, and the way
is spelled the same at nine sites in this tree. What separates the two that bit
from the seven that did not is nothing about the filter -- it is whether the
walked root comes from OUTSIDE the repo. `upstream_root()` returns a path the
environment chooses, so an ancestor named `target` is somebody else's decision;
`CRATES` is `<repo>/crates`, so today no ancestor is named `target` and the
absolute test is accidentally equivalent. That accident is the whole defence,
and it holds only while nobody clones this repo under a directory called
`target` -- or, for the two sites that exclude `tests` and `benches` rather
than `target`, under a directory called either of those.

So the population is not "walks of the upstream checkout". It is every
membership test on a path's components, and the rule has no exemption list:
testing the RELATIVE path is correct at all of them and weaker at none, which
is why every site can be brought to it instead of a table saying which sites
are allowed to be wrong.

## What is graded

Population, derived from the AST of every tracked `*.py`: each `<str> in
<expr>.parts` membership test. A test PASSES when `<expr>` is a
`.relative_to(...)` result -- directly, or a local name bound only from one.
It FAILS when the tested path is the raw walk variable.

The population floor is a MINIMUM, not a budget: it reds when the tests
disappear, because a lint whose population went to zero reports green while
grading nothing. It is deliberately not an upper bound -- a new walk that
excludes a build directory relatively is a correct new walk, and a check that
made an author lower a number to write one would be teaching the wrong lesson.
"""

from __future__ import annotations

import ast
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# A MINIMUM. Measured at 11 when this gate was written (9 absolute, 2 already
# relative). See the docstring on why there is no ceiling.
POPULATION_FLOOR = 8


class InputError(RuntimeError):
    """The lint could not read what it grades."""


def tracked_python(root: pathlib.Path) -> list[pathlib.Path]:
    """Every tracked `*.py`, from the tree's own VCS rather than a glob.

    `git ls-files` and not `rglob` so an untracked scratch copy cannot pad the
    population -- and so a file this gate is meant to grade has to be STAGED
    before it counts, which is the R2191 rule for a population gate reading its
    own tree.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "*.py"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise InputError(f"cannot list tracked python ({exc})") from exc
    return [root / line for line in out.splitlines() if line]


_FUNC = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _own_nodes(scope: ast.AST):
    """Every node of `scope` that a NESTED function does not own.

    `ast.walk` descends into nested definitions, and that is precisely the
    laundering this lint must not do: a `rel = path.relative_to(root)` inside
    one function would otherwise vouch for a bare `rel` in its sibling. The
    selftest holds that case, and it is what caught this being written the
    easy way first.
    """
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, _FUNC):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _bindings(scope: ast.AST) -> tuple[set[str], set[str]]:
    """`(bound from relative_to, bound from anything else)` in this scope."""
    from_rel: set[str] = set()
    from_other: set[str] = set()
    for node in _own_nodes(scope):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        relative = (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "relative_to"
        )
        for target in targets:
            if isinstance(target, ast.Name):
                (from_rel if relative else from_other).add(target.id)
    return from_rel, from_other


def _relative_names(chain: list[ast.AST]) -> set[str]:
    """Names the scope CHAIN binds only from a `.relative_to(...)` call.

    The chain and not one scope, because a function really does read the names
    its enclosing scopes bind. "Only" matters in the other direction: a name
    that is relative on one branch and absolute on another is not a name this
    lint can call safe, and treating it as safe would be the escape hatch the
    docstring refuses.
    """
    from_rel: set[str] = set()
    from_other: set[str] = set()
    for scope in chain:
        rel, other = _bindings(scope)
        from_rel |= rel
        from_other |= other
    return from_rel - from_other


def _scope_chains(tree: ast.Module) -> list[list[ast.AST]]:
    """Every scope, as the chain of scopes enclosing it, module first."""
    chains: list[list[ast.AST]] = []

    def walk(scope: ast.AST, enclosing: list[ast.AST]) -> None:
        chain = enclosing + [scope]
        chains.append(chain)
        for node in _own_nodes(scope):
            if isinstance(node, _FUNC):
                walk(node, chain)

    walk(tree, [])
    return chains


def parts_tests(path: pathlib.Path, text: str) -> list[tuple[int, str, bool]]:
    """`(line, source, is_relative)` for each `<str> in <expr>.parts` test."""
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise InputError(f"{path} does not parse ({exc})") from exc

    # Each test is judged exactly ONCE, in the scope that owns it, against the
    # names that scope's chain binds. `_own_nodes` is what makes "owns" true:
    # visiting a test from an outer scope as well would judge it against names
    # it cannot see, and merging the two verdicts would take the laxer one.
    verdicts: dict[tuple[int, str], bool] = {}
    for chain in _scope_chains(tree):
        safe = _relative_names(chain)
        for node in _own_nodes(chain[-1]):
            if not isinstance(node, ast.Compare):
                continue
            # `not in` as well as `in`: `if "target" not in path.parts: keep()`
            # is the same test wearing the opposite sign, and it fails in the
            # same direction -- an ancestor named `target` makes it keep
            # nothing. Grading only `in` would leave the class a spelling away.
            if len(node.ops) != 1 or not isinstance(node.ops[0], (ast.In, ast.NotIn)):
                continue
            target = node.comparators[0]
            if not (isinstance(target, ast.Attribute) and target.attr == "parts"):
                continue
            value = target.value
            relative = (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr == "relative_to"
            ) or (isinstance(value, ast.Name) and value.id in safe)
            verdicts[(node.lineno, ast.unparse(node))] = relative
    return [(line, src, rel) for (line, src), rel in sorted(verdicts.items())]


def audit(root: pathlib.Path) -> tuple[list[str], int]:
    """`(offenders, population)` over every tracked python file."""
    offenders: list[str] = []
    population = 0
    for path in tracked_python(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise InputError(f"{path} is not readable ({exc})") from exc
        for line, src, relative in parts_tests(path, text):
            population += 1
            if not relative:
                rel = path.relative_to(root).as_posix()
                offenders.append(f"{rel}:{line}  {src}")
    return offenders, population


def selftest() -> int:
    """Drive the classifier in BOTH directions over synthetic sources."""
    failures: list[str] = []

    def expect(label: str, source: str, want_relative: bool) -> None:
        got = parts_tests(pathlib.Path("<selftest>"), source)
        if len(got) != 1:
            failures.append(f"{label}: expected exactly one test, got {got}")
            return
        if got[0][2] != want_relative:
            verdict = "relative" if got[0][2] else "absolute"
            failures.append(f"{label}: read as {verdict}")

    # The shape that bit: the raw walk variable.
    expect(
        "an absolute parts test is caught",
        "def f(root):\n"
        "    for path in root.rglob('*.rs'):\n"
        "        if 'target' in path.parts:\n"
        "            continue\n",
        False,
    )
    # The repair, in both spellings the tree uses.
    expect(
        "a bound relative name passes",
        "def f(root):\n"
        "    for path in root.rglob('*.rs'):\n"
        "        rel = path.relative_to(root)\n"
        "        if 'target' in rel.parts:\n"
        "            continue\n",
        True,
    )
    expect(
        "an inline relative_to passes",
        "def f(root):\n"
        "    for path in root.rglob('*.rs'):\n"
        "        if 'target' in path.relative_to(root).parts:\n"
        "            continue\n",
        True,
    )
    # A name that is relative on one branch and absolute on another is NOT
    # safe. Without this the repair could be faked by binding the name once.
    expect(
        "a name rebound from an absolute path is caught",
        "def f(root, other):\n"
        "    for path in root.rglob('*.rs'):\n"
        "        rel = path.relative_to(root)\n"
        "        if other:\n"
        "            rel = path\n"
        "        if 'target' in rel.parts:\n"
        "            continue\n",
        False,
    )
    # A relative binding in a DIFFERENT function must not launder this one.
    expect(
        "a relative name from another function does not carry",
        "def g(root, path):\n"
        "    rel = path.relative_to(root)\n"
        "    return rel\n"
        "def f(root):\n"
        "    for rel in root.rglob('*.rs'):\n"
        "        if 'target' in rel.parts:\n"
        "            continue\n",
        False,
    )

    # The opposite sign is the same defect, so it is in the population.
    expect(
        "an absolute `not in` test is caught too",
        "def f(root):\n"
        "    for path in root.rglob('*.rs'):\n"
        "        if 'target' not in path.parts:\n"
        "            keep(path)\n",
        False,
    )

    # Things that are NOT this test, so the population cannot be padded.
    for label, source in (
        ("an index into parts is not a membership test", "n = path.parts[0]\n"),
        ("a length of parts is not one", "n = len(path.parts)\n"),
        ("a membership test on something else is not one", "if 'a' in path.name:\n    pass\n"),
    ):
        got = parts_tests(pathlib.Path("<selftest>"), source)
        if got:
            failures.append(f"{label}: counted {got}")

    # The floor, RUN rather than declared: a population under it must refuse.
    if POPULATION_FLOOR <= 0:
        failures.append("the population floor cannot fail")

    for line in failures:
        print(f"  root-relative-exclusion: SELFTEST FAIL -- {line}")
    if failures:
        return 1
    print(
        "  root-relative-exclusion: selftest ok -- absolute caught, relative "
        "passes, a rebound name is not laundered"
    )
    return 0


def main(argv: list[str]) -> int:
    unknown = [a for a in argv if a not in ("--selftest", "--verbose")]
    if unknown:
        print(f"  root-relative-exclusion: unknown argument(s): {' '.join(unknown)}")
        return 2
    if "--selftest" in argv:
        return selftest()

    try:
        offenders, population = audit(REPO_ROOT)
    except InputError as exc:
        print(f"  root-relative-exclusion: INPUT -- {exc}")
        return 2

    if population < POPULATION_FLOOR:
        print(
            f"  root-relative-exclusion: INPUT -- graded {population} parts "
            f"test(s), under the floor of {POPULATION_FLOOR}. A lint whose "
            f"population went to zero reports green while grading nothing"
        )
        return 2

    if offenders:
        print(
            f"  root-relative-exclusion: FAIL -- {len(offenders)} of "
            f"{population} exclusion(s) test a path's components on the "
            f"ABSOLUTE path. Whether that is equivalent to the relative one "
            f"is a fact about where the walked root happens to sit, which is "
            f"the environment's choice and not this file's:"
        )
        for line in offenders:
            print(f"    {line}")
        return 1

    if "--verbose" in argv:
        for path in tracked_python(REPO_ROOT):
            for line, src, _ in parts_tests(
                path, path.read_text(encoding="utf-8", errors="replace")
            ):
                print(f"    {path.relative_to(REPO_ROOT).as_posix()}:{line}  {src}")
    print(
        f"  root-relative-exclusion: {population} path-component exclusion(s), "
        f"every one tested on a path relative to the root its walk was given"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
