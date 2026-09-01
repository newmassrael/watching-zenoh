#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2247 (no register item) -- an arming flag has to be read on EVERY branch
that declines to run.

Closes item 598 of the unregistered register, which lives outside this
repository -- which is why the citation above reads "no register item", the
same position `armed_oracle_census.py` records for 562 and
`cdylib_soname_gate.py` for 521. The item is named in full here, which is what
a reader grepping for it will find.

## The failure this ends

A lane that needs a machine-local oracle SKIPs when the oracle is absent, and a
`WZ_..._REQUIRE` flag turns that skip into a failure on the job that PROVISIONS
it. That is the tree's standing answer to "a population of zero reports green".

The flag is read at one branch, and lanes decline at several. Layer C1ce had two
declines and consulted `WZ_C1CE_REQUIRE` at the first: with the flag armed and
the examples clone moved away, the lane printed `pass (0s)` and `run-ci: all
required layers pass`, having compiled nothing. Layer Q was the same shape at
scale -- thirteen declines, two of which consulted `WZ_Q_REQUIRE`, under a job
whose own comment says "any footprint SKIP here is a provisioning regression".

So the flag existing is not the property anybody wanted. The property is that
every decline is behind it, and nothing measured that.

## Why this is a different gate from `armed_oracle_census.py`

That file walks the armings run-ci.sh SETS -- `WZ_..._REQUIRE=1 cargo ...` --
and asks what the machine must already have. This one walks the armings a lane
READS. The two populations are disjoint by construction, which is exactly why
the census was green across every round C1ce was broken.

## What is derived, and what would be an escape hatch

The population is derived twice over and there is no exemption table:

  * GUARD -- every tracked `scripts/**.sh`, parsed into scopes (a function, or
    the file's top level). A scope that reads a handle is ARMED; in an armed
    scope every SKIP notice must have the handle read on a path that DOMINATES
    it (the same block, or an enclosing one, lexically earlier). A read through
    a variable the handle was assigned to counts -- `lint_required` and
    `m_required` are that shape and they are real guards.

  * GUARD, Python -- the same question of `scripts/lib/*.py`, over the AST
    rather than the text. Two gates read a flag from `os.environ` and decline
    in Python, and a rule that only walked shell would have said "no finding"
    about a language it never opened. Both were measured correct on the day
    this was written; that is a fact about today, and the reason to walk them
    is that nothing was keeping it true.

  * CONSUME -- the tree's answer to a lane with many declines is a helper
    (`_z_unavailable`, `_q_unavailable`), which moves the SKIP text out of the
    lane and would move it out of the GUARD population with it. A helper whose
    non-zero return nobody reads is the same hole one level up, so every call to
    an arming helper must consume its status: a `||`/`&&` list, an `if`/`while`
    condition, a `!`, or a following `return $?`.

  * LIVE -- a `WZ_..._REQUIRE` NAMED on the lane surface must be read or set
    somewhere in the tree. `run-ci.sh` claimed a WZ_C1BC_REQUIRE=1 prefix turned
    a skip into a failure; no such name is read anywhere, and the paragraph is
    about C1ce's neighbour C1cc. A flag nobody reads arms nothing, and prose is
    where that is invisible.

Python sources are on the LIVE axis's naming side too, minus their string
literals -- tokenized, not regexed. That distinction is structural rather than
an exemption: `armed_oracle_census.py` carries WZ_X_REQUIRE and WZ_NEW_REQUIRE
inside a docstring and a selftest fixture, which are names of nothing on
purpose, while a typo in a `#` comment is a claim like any other.

⚠ Those three flag names are deliberately NOT written as code spans here.
R2253 (open-debt item 601) removed the `hypothetical` kind from
`prose_named_identifier_gate.py`, which had been the way a nonexistent name
kept a code span: a span holding one identifier asserts the identifier exists,
so a sentence ABOUT a name's absence spells it in plain text.

An empty population FAILs. Every assertion here is about a set, an empty set
agrees with everything, and if the last armed lane genuinely goes then this
floor comes down in the commit that removed it.
"""

from __future__ import annotations

import argparse
import ast
import io
import pathlib
import re
import subprocess
import sys
import tempfile
import tokenize

ROOT = pathlib.Path(__file__).resolve().parents[2]

HANDLE = re.compile(r"WZ_[A-Z0-9_]*_REQUIRE")

#: `name() {` on a line of its own -- the shape every function in this tree's
#: shell has. A one-line function body would not be a scope worth walking.
FUNC = re.compile(r"^\s*(?:function\s+)?([A-Za-z0-9_]+)\s*\(\)\s*\{\s*$")

#: A SKIP NOTICE: the lane telling a reader it declined. `echo`/`print` rather
#: than any line containing the word, so a comment about skipping and a variable
#: named `skip_reason` are not mistaken for one.
SKIP_NOTICE = re.compile(r"\bSKIP\b")

#: The branch REPORTING FAILURE, which is what separates a decline from a
#: failure that explains itself. `cdylib_soname_gate.py` prints "This is a FAIL
#: and not a SKIP because a gate that cannot read its input must not report
#: green" and then returns 1: the word is in it and the property is not. The
#: subject here is the CONSEQUENCE -- declined AND still reported success -- so
#: that is what gets read, rather than a vocabulary this gate would then own.
REPORTS_FAILURE = re.compile(
    r"\breturn\s+[1-9]|\bexit\s+[1-9]|\bfail=1\b|\brc=1\b|\breturn\s+\"?\$fail"
)

#: The status of a call is consumed when it decides something. `;` before
#: `return $?` is the `_qz_unavailable` shape; `||`/`&&` is every other one.
CONSUMED = (
    re.compile(r"\|\||&&"),
    re.compile(r"^\s*(?:if|while|until)\b"),
    re.compile(r"^\s*!\s"),
    re.compile(r";\s*return\s+\$\?"),
)


def shell_sources() -> list[pathlib.Path]:
    out = subprocess.run(
        ["git", "ls-files", "scripts"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [ROOT / p for p in out if p.endswith(".sh")]


def units(text: str) -> list[tuple[int, str]]:
    """Fold `\\`-continued lines into one unit, keyed by the FIRST line number.

    A guard and the notice it guards are routinely written across a
    continuation (`[[ ... ]] \\` / `&& lint_required=1`), and reading those as
    two lines loses the assignment that makes the guard a guard.
    """
    out: list[tuple[int, str]] = []
    buf: str | None = None
    start = 0
    for number, line in enumerate(text.split("\n"), 1):
        if buf is None:
            start, buf = number, line
        else:
            buf += " " + line.strip()
        if line.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1]
            continue
        out.append((start, buf))
        buf = None
    if buf is not None:
        out.append((start, buf))
    return out


class Line:
    __slots__ = ("number", "text", "block", "ancestry", "scope")

    def __init__(self, number: int, text: str, block: int, ancestry: tuple[int, ...], scope: str):
        self.number = number
        self.text = text
        self.block = block
        self.ancestry = ancestry
        self.scope = scope

    @property
    def comment(self) -> bool:
        return self.text.lstrip().startswith("#")


def parse(text: str) -> list[Line]:
    """Give every unit its innermost block and the chain of blocks enclosing it.

    Dominance is the question, so what matters is the ANCESTRY: a guard in a
    sibling block does not run on the path that reaches this notice, which is
    precisely how C1ce's second decline looked guarded to a reader.
    """
    stack = [0]
    scope = ["<top>"]
    nxt = 1
    out: list[Line] = []
    for number, text_ in units(text):
        stripped = text_.strip()
        if stripped.startswith("#"):
            out.append(Line(number, text_, stack[-1], tuple(stack), scope[-1]))
            continue
        if re.match(r"^(fi|done|esac)\b", stripped):
            if len(stack) > 1:
                stack.pop()
        elif re.match(r"^(else|elif)\b", stripped):
            if len(stack) > 1:
                stack.pop()
            stack.append(nxt)
            nxt += 1
        elif re.match(r"^\}\s*$", stripped) and len(scope) > 1:
            scope.pop()
            if len(stack) > 1:
                stack.pop()
        out.append(Line(number, text_, stack[-1], tuple(stack), scope[-1]))
        match = FUNC.match(stripped)
        if match:
            scope.append(match.group(1))
            stack.append(nxt)
            nxt += 1
            continue
        if (
            re.search(r";\s*then\s*$", stripped)
            or stripped == "then"
            or re.search(r";\s*do\s*$", stripped)
            or stripped == "do"
            or re.search(r"\bcase\b.*\bin\s*$", stripped)
        ):
            stack.append(nxt)
            nxt += 1
    return out


def scopes(lines: list[Line]) -> dict[str, list[Line]]:
    out: dict[str, list[Line]] = {}
    for line in lines:
        out.setdefault(line.scope, []).append(line)
    return out


def guard_lines(body: list[Line]) -> list[Line]:
    """Reads of a handle, plus reads of any variable a handle was assigned to.

    The alias set is DERIVED from the assignment, not listed: a lane that
    resolves the flag once into `m_required` and branches on that is guarded,
    and a gate that could not see it would push lanes towards copying the
    `[[ -n "${WZ_..._REQUIRE:-}" ]]` test per branch -- which is the defect.
    """
    direct = [line for line in body if not line.comment and HANDLE.search(line.text)]
    aliases: set[str] = set()
    for line in direct:
        for match in re.finditer(r"\b([a-z_][a-z0-9_]*)=", line.text):
            aliases.add(match.group(1))
    guards = list(direct)
    if aliases:
        pattern = re.compile(r"\b(?:" + "|".join(sorted(aliases)) + r")\b")
        guards += [
            line
            for line in body
            if not line.comment and line not in direct and pattern.search(line.text)
        ]
    return sorted(guards, key=lambda line: line.number)


def arming_helpers(lines: list[Line]) -> set[str]:
    """Functions that ARE the arming: they read a handle, notice, and can fail."""
    found: set[str] = set()
    for name, body in scopes(lines).items():
        if name == "<top>":
            continue
        code = [line for line in body if not line.comment]
        if not any(HANDLE.search(line.text) for line in code):
            continue
        if not any(SKIP_NOTICE.search(line.text) for line in code):
            continue
        if not any(re.search(r"\breturn\s+1\b", line.text) for line in code):
            continue
        found.add(name)
    return found


def unguarded(lines: list[Line]) -> list[tuple[Line, str]]:
    out: list[tuple[Line, str]] = []
    for name, body in scopes(lines).items():
        guards = guard_lines(body)
        if not guards:
            continue
        for line in body:
            if line.comment or not SKIP_NOTICE.search(line.text):
                continue
            if "echo" not in line.text and "print" not in line.text:
                continue
            if any(g.number < line.number and g.block in line.ancestry for g in guards):
                continue
            later = [
                other
                for other in body
                if other.number > line.number
                and other.block == line.block
                and not other.comment
            ]
            if any(REPORTS_FAILURE.search(other.text) for other in later):
                continue
            out.append((line, name))
    return sorted(out, key=lambda pair: pair[0].number)


def unconsumed(lines: list[Line], helpers: set[str]) -> list[tuple[Line, str]]:
    out: list[tuple[Line, str]] = []
    for line in lines:
        if line.comment:
            continue
        for helper in helpers:
            if not re.search(rf"(?<![\w-]){re.escape(helper)}\b", line.text):
                continue
            if FUNC.match(line.text.strip()):
                continue
            if any(pattern.search(line.text) for pattern in CONSUMED):
                continue
            out.append((line, helper))
    return out


def _mentions(node: ast.AST, needles: set[str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in needles:
            return True
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if HANDLE.search(child.value):
                return True
        if isinstance(child, ast.Attribute) and child.attr in needles:
            return True
    return False


def _tainted(tree: ast.AST) -> set[str]:
    """Names a handle's value flowed into -- `required = os.environ.get(...)`."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            continue
        value = node.value
        if value is None or not _mentions(value, names):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
    return names


def _skip_notice(node: ast.stmt) -> bool:
    """A `print(...)` whose text says SKIP -- the STATEMENT, not its subtree.

    Asking `ast.walk` whether a compound statement contains such a string says
    yes for the `if` several levels above it too, and the guard sits BETWEEN
    them. That mistake reported both gates in this tree as broken while they
    were correct; the control fixture is what caught it.
    """
    if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
        return False
    call = node.value
    if not isinstance(call.func, ast.Name) or call.func.id != "print":
        return False
    for child in ast.walk(call):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if SKIP_NOTICE.search(child.value):
                return True
    return False


def python_unguarded(path: pathlib.Path) -> list[tuple[int, str]]:
    """SKIP notices in a Python gate that reads a flag but not on this branch.

    Same dominance rule as the shell arm, expressed over statement lists: a
    guard is an enclosing `if` whose test mentions the flag, or an EARLIER
    sibling `if` that does -- which is the `if required: ... return 1` /
    `print(SKIP)` shape both gates in this tree actually use.
    """
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return []
    if not HANDLE.search(source):
        return []
    tree = ast.parse(source)
    # Two passes: the taint set can be assigned after a use lexically, and a
    # single pass would then read a real guard as an unrelated name.
    tainted = _tainted(tree)
    tainted |= _tainted(tree)
    findings: list[tuple[int, str]] = []

    def reports_failure(body: list[ast.stmt], after: int) -> bool:
        for statement in body[after + 1 :]:
            if isinstance(statement, ast.Raise):
                return True
            if isinstance(statement, ast.Return):
                value = statement.value
                return isinstance(value, ast.Constant) and bool(value.value)
        return False

    def walk(body: list[ast.stmt], guarded: bool, scope: str) -> None:
        seen_guard = guarded
        for index, statement in enumerate(body):
            if isinstance(statement, ast.If) and _mentions(statement.test, tainted):
                walk(statement.body, True, scope)
                walk(statement.orelse, True, scope)
                seen_guard = True
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # A guard resolved in the caller does not run on this path; the
                # function is its own scope, exactly as a shell function is.
                walk(statement.body, False, statement.name)
                continue
            if not seen_guard and _skip_notice(statement):
                if not reports_failure(body, index):
                    findings.append((statement.lineno, scope))
                continue
            for field in ("body", "orelse", "finalbody"):
                inner = getattr(statement, field, None)
                if isinstance(inner, list):
                    walk(inner, seen_guard, scope)
    walk(tree.body, False, "<module>")
    return findings


def python_named(path: pathlib.Path) -> set[str]:
    """Handle names a Python source NAMES -- code and comments, not literals."""
    found: set[str] = set()
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return found
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.STRING:
                continue
            found |= set(HANDLE.findall(token.string))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # A file this gate cannot tokenize is one it cannot classify, and
        # unclassified is not a pass.
        raise
    return found


def python_env_reads(path: pathlib.Path) -> set[str]:
    """Flags a Python source READS from the environment.

    An AST question, not a text one, and that distinction is load-bearing in
    BOTH directions. A flag name inside `os.environ.get("...")` is a string
    literal and is a real read; a flag name inside any OTHER string is prose.
    The first version of this gate read liveness off the text and so its own
    docstring -- which quotes a WZ_C1BC_REQUIRE=1 prefix while explaining that
    nothing reads it -- marked that flag live. A gate whose prose satisfies
    its own predicate has stopped being a gate.
    """
    found: set[str] = set()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return found
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Call, ast.Subscript)):
            continue
        source = ast.dump(node.func) if isinstance(node, ast.Call) else ast.dump(node.value)
        if "environ" not in source and "getenv" not in source:
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                found |= set(HANDLE.findall(child.value))
    return found


def surface() -> tuple[set[str], set[str], dict[str, list[str]]]:
    """`(named, live, where)` across the tree's own gate surface.

    NAMED is a claim -- the text asserts something about the flag. LIVE is a
    reader or a setter. Each language answers both questions its own way,
    because the same characters mean different things: `"WZ_X"` is prose in a
    docstring and a read inside `os.environ.get`.
    """
    listed = subprocess.run(
        ["git", "ls-files", "scripts", ".github", "crates"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    named: set[str] = set()
    live: set[str] = set()
    where: dict[str, list[str]] = {}
    for rel in listed:
        path = ROOT / rel
        if path.suffix == ".py":
            named |= python_named(path)
            for handle in python_env_reads(path):
                live.add(handle)
                where.setdefault(handle, []).append(rel)
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(text.split("\n"), 1):
            stripped = line.lstrip()
            comment = stripped.startswith("#") or stripped.startswith("//")
            for handle in set(HANDLE.findall(line)):
                if path.suffix in (".sh", ".yml", ".yaml"):
                    named.add(handle)
                if comment:
                    continue
                if path.suffix == ".rs":
                    if "env::var" in line or "environ" in line:
                        live.add(handle)
                        where.setdefault(handle, []).append(f"{rel}:{number}")
                    continue
                read = re.search(rf"\$\{{{handle}[:\-}}]", line) or re.search(
                    rf"\${handle}\b", line
                )
                assign = re.search(rf"\b{handle}\s*[:=]", line)
                if read or assign:
                    live.add(handle)
                    where.setdefault(handle, []).append(f"{rel}:{number}")
    return named, live, where


def check(root: pathlib.Path | None = None) -> int:
    findings: list[str] = []
    sources = shell_sources() if root is None else sorted(root.rglob("*.sh"))
    armed_scopes = 0
    for path in sources:
        try:
            lines = parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as err:
            findings.append(f"armed-skip: {path} is unreadable ({err})")
            continue
        rel = path.relative_to(root if root is not None else ROOT)
        for name, body in scopes(lines).items():
            if guard_lines(body):
                armed_scopes += 1
        for line, scope in unguarded(lines):
            findings.append(
                f"{rel}:{line.number}: `{scope}` reads a WZ_..._REQUIRE flag and "
                f"this decline does not -- with the flag armed the lane reports "
                f"pass having run nothing here. Put the flag on THIS branch, or "
                f"route the decline through an arming helper. "
                f"[{line.text.strip()[:60]}]"
            )
        helpers = arming_helpers(lines)
        for line, helper in unconsumed(lines, helpers):
            findings.append(
                f"{rel}:{line.number}: `{helper}` returns non-zero when its flag "
                f"is armed and this call reads no status, so the arming is lost "
                f"at the call rather than at the branch. "
                f"[{line.text.strip()[:60]}]"
            )

    python_sources = (
        sorted((ROOT / "scripts").rglob("*.py"))
        if root is None
        else sorted(root.rglob("*.py"))
    )
    for path in python_sources:
        if path.resolve() == pathlib.Path(__file__).resolve():
            # This file NAMES the shape it hunts, in fixtures. Walking itself
            # would grade the description instead of the described.
            continue
        rel = path.relative_to(root if root is not None else ROOT)
        try:
            found = python_unguarded(path)
        except SyntaxError as err:
            findings.append(f"{rel}: unparseable, so unclassified ({err})")
            continue
        if HANDLE.search(path.read_text(encoding="utf-8")):
            armed_scopes += 1
        for number, scope in found:
            findings.append(
                f"{rel}:{number}: `{scope}` reads a WZ_..._REQUIRE flag from the "
                f"environment and this decline is not behind it, so the gate "
                f"reports green on a machine it never graded."
            )

    if root is None:
        named, live, where = surface()
        for handle in sorted(named - live):
            findings.append(
                f"`{handle}` is named on the lane surface and nothing reads or "
                f"sets it anywhere in this tree. A flag nobody reads arms "
                f"nothing; either the name is a typo for a live one or the text "
                f"describes an arming that was never built."
            )
        if not live:
            findings.append(
                "armed-skip: no WZ_..._REQUIRE flag is live anywhere. Every "
                "assertion here is about a population and an empty one agrees "
                "with everything; if the last arming has genuinely gone, this "
                "floor comes down in the same commit that removed it."
            )
        del where

    if not armed_scopes:
        findings.append(
            "armed-skip: no shell scope reads a WZ_..._REQUIRE flag at all, so "
            "the GUARD axis walked nothing. Same floor, same reason."
        )

    for finding in findings:
        print(f"armed-skip FAIL: {finding}")
    if findings:
        return 1
    print(
        f"armed-skip: OK -- {armed_scopes} armed shell scope(s); every decline "
        f"reads its flag, every arming-helper call reads its status, and every "
        f"flag named on the lane surface is live."
    )
    return 0


#: Fixtures the PREVIOUS implementation swallowed. `c1ce` is the exact shape
#: item 598 was filed for -- two declines, the flag on the first -- and `q` is
#: the helper hole one level up. `good` is the control: it must PASS, so a gate
#: that simply reds is not mistaken for one that discriminates.
FIXTURES: dict[str, tuple[str, bool]] = {
    "c1ce.sh": (
        """\
lane_two_declines() {
    if [[ ! -f "$oracle" ]]; then
        if [[ -n "${WZ_FIX_REQUIRE:-}" ]]; then
            echo "  FAIL required" >&2
            return 1
        fi
        echo "  Lane SKIP (no oracle)"
        return 0
    fi
    if [[ ! -f "$examples" ]]; then
        echo "  Lane SKIP (no examples)"
        return 0
    fi
    return 0
}
""",
        False,
    ),
    "helper.sh": (
        """\
_fix_unavailable() {
    if [[ -n "${WZ_FIX_REQUIRE:-}" ]]; then
        echo "  FAIL required" >&2
        return 1
    fi
    echo "  Lane SKIP ($1)"
    return 0
}

lane_bare_call() {
    if [[ ! -f "$oracle" ]]; then
        _fix_unavailable "no oracle"
        return 0
    fi
    return 0
}
""",
        False,
    ),
    "pygate.py": (
        '''\
import os


def main():
    required = os.environ.get("WZ_FIX_REQUIRE", "") not in ("", "0")
    if not os.path.isfile("/oracle"):
        if required:
            print("gate FAIL: required but absent")
            return 1
        print("gate SKIP: no oracle")
        return 0
    if not os.path.isfile("/examples"):
        print("gate SKIP: no examples")
        return 0
    return 0
''',
        False,
    ),
    "pygate_good.py": (
        '''\
import os


def main():
    required = os.environ.get("WZ_FIX_REQUIRE", "") not in ("", "0")
    if not os.path.isfile("/oracle"):
        if required:
            print("gate FAIL: required but absent")
            return 1
        print("gate SKIP: no oracle")
        return 0
    if not os.path.isfile("/examples"):
        if required:
            print("gate FAIL: required but absent")
            return 1
        print("gate SKIP: no examples")
        return 0
    return 0
''',
        True,
    ),
    "good.sh": (
        """\
_fix_unavailable() {
    if [[ -n "${WZ_FIX_REQUIRE:-}" ]]; then
        echo "  FAIL required" >&2
        return 1
    fi
    echo "  Lane SKIP ($1)"
    return 0
}

lane_alias_guard() {
    local need=0
    [[ "${WZ_FIX_REQUIRE:-0}" == "1" ]] \\
        && need=1
    if [[ ! -f "$oracle" ]]; then
        if [[ "$need" == "1" ]]; then
            echo "  FAIL required" >&2
            return 1
        fi
        echo "  Lane SKIP (no oracle)"
        return 0
    fi
    if [[ ! -f "$examples" ]]; then
        _fix_unavailable "no examples" || return 1
    fi
    return 0
}
""",
        True,
    ),
}


def selftest() -> int:
    bad = 0
    for name, (body, want_pass) in sorted(FIXTURES.items()):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / name).write_text(body, encoding="utf-8")
            rc = check(root=root)
        ok = (rc == 0) == want_pass
        print(
            f"armed-skip selftest {name}: rc={rc} "
            f"want={'pass' if want_pass else 'fail'} {'ok' if ok else 'WRONG'}"
        )
        if not ok:
            bad = 1
    return bad


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="walk this tree")
    parser.add_argument("--selftest", action="store_true", help="drive the fixtures")
    args = parser.parse_args()
    if args.check == args.selftest:
        parser.error("pass exactly one of --check / --selftest")
    return selftest() if args.selftest else check()


if __name__ == "__main__":
    sys.exit(main())
