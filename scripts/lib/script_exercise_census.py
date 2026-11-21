#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4582 (no register item) -- every script under scripts/ is exercised by a lane, or a row here
says why no lane runs it.

## The defect, measured

A tool no lane runs rots without a sound. On 2026-11-21 two were found by hand, a day apart:
scripts/host-bench/perf_matrix.py called a function a merge had dropped, and every performance
run of that day came back NOT-MEASURED; scripts/lib/pico_windows_package.py carried a selftest
that no lane ran. Both got Layer C0 selftest legs, and nothing stopped the third tool. Read on
the tree it was written on, this census found 40 scripts that no lane, workflow step or
exercised script reached.

## The population

Every TRACKED file under scripts/ that is a python or shell script (a .py or .sh name) or an
executable script of another name (its first line is a shebang), at any depth. Left out by rule,
not by list: a path with a vendored segment (vendor/, third-party/), and a file whose first ten
lines carry a generated-file header (a comment opening with GENERATED, the convention of this
tree's generators, or @generated). Neither exists under scripts/ today; the rule is held by the
selftest so the first one is left out without an edit here.

## The classes, each script in exactly one

RUN         invoked by a non-comment line of scripts/run-ci.sh, of a workflow's run step under
            .github/workflows/, or of a composite action's run step under .github/actions/; or
            invoked by a script that is itself RUN (a shell line, or a subprocess call of a
            python script, read by the reader round_fed_gate_reach.py already uses for "does
            a push run this gate").
SELFTESTED  invoked only with --selftest by such a line (a Layer C0 leg, as a rule), or by the
            selftest of a SELFTESTED shell script that hands --selftest on.
IMPORTED    a python module imported by a RUN or SELFTESTED python script, or by one imported
            by those: it is exercised through its importer.
DECLARED    in the DECLARED table below with a reason and the owner action that exercises it.

The classes are read in that order, so a script invoked both ways is RUN. A DECLARED row whose
script is in an earlier class is stale and fails: the table can only shrink by the work it names.

## How an invocation is read

Shell text (run-ci.sh, every RUN shell script, and the run steps of the workflows with every
other line of the YAML blanked) is scanned once for what is shell CODE: single- and double-quoted
strings, comments and heredoc bodies are not, a command substitution inside a double-quoted
string is. An invocation is a script path in code after an interpreter (python, python3, bash,
sh, source, exec), at a command position (a line start that does not continue the line before
it, after a separator or a keyword, behind variable assignments or a program held in a variable),
or bound to a variable. So a message that names a script, a path handed to git as an argument,
an awk program and a heredoc are not invocations, and the selftest holds each of those.

A path resolves by its literal tail: the segments after the last variable, a dirname
substitution or a parent step. A tail that names more than one script resolves only to the one
in the invoking script's own directory, and otherwise to none: a guess between two would be a
false RUN, the one error a census of this kind must not make.

## Why the git hooks are not a root

The pre-push hook's round-fed sweep is opt-in (WZ_PREPUSH_EXTENDED=1, owner decision 2026-09-23),
and a gate only the hook runs is not graded by any lane. A script that only a hook runs is
therefore DECLARED, with the hook named in its row.

## What this does not see

A program reached through PATH (the cargo shim of the artifact root, which a subprocess call
naming cargo does not reach by name) or spelled through a variable assembled at run time is
unread; each such script is a DECLARED row. A selftest of a python script that runs another
script is not followed: which arm of it runs the other is not a fact of the text. Both errors
are in the loud direction, a row someone has to write.
"""

from __future__ import annotations

import argparse
import ast
import posixpath
import re
import subprocess
import sys
import warnings
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import round_fed_gate_reach  # noqa: E402  -- the reader of a python gate's subprocess calls

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = "scripts/"
LIB = "scripts/lib/"
RUN_CI = "scripts/run-ci.sh"
WORKFLOWS = ".github/workflows/"
ACTIONS = ".github/actions/"
YAML_SUFFIX = (".yml", ".yaml")
ACTION_NAMES = ("action.yml", "action.yaml")
VENDORED_SEGMENTS = frozenset({"vendor", "third-party", "third_party"})
GENERATED_HEADER = re.compile(r"^\s*(?:#|//)\s*(?:GENERATED\b|@generated\b)")
HEAD_LINES = 10

RUN = "RUN"
SELFTESTED = "SELFTESTED"
IMPORTED = "IMPORTED"
DECLARED_CLASS = "DECLARED"
UNCLASSIFIED = "UNCLASSIFIED"
CLASS_ORDER = (RUN, SELFTESTED, IMPORTED, DECLARED_CLASS, UNCLASSIFIED)

#: script -> (why no lane runs it, the owner action that exercises it). Removing a row is free;
#: a row needs both strings, a script of the population, and that script in no other class.
DECLARED: dict[str, tuple[str, str]] = {
    "scripts/capture-validation.sh": (
        "captures the validation corpus of the flow verdict in docker containers, once per "
        "corpus revision; no lane has docker or the pinned release's programs",
        "run by hand when the validation corpus is recaptured (docs/flow-zenoh-verdict.md 6.12)",
    ),
    "scripts/capture-validation/build-bins.sh": (
        "builds the pinned release's programs the validation corpus is captured with",
        "run through bx before scripts/capture-validation.sh when the corpus is recaptured",
    ),
    "scripts/capture-validation/build-c-pico.sh": (
        "builds the zenoh-c and zenoh-pico examples the validation corpus is captured with",
        "run by hand before scripts/capture-validation.sh when the corpus is recaptured",
    ),
    "scripts/capture-validation/null-workload.sh": (
        "one null protocol of the validation corpus, run by scripts/capture-validation.sh",
        "runs whenever scripts/capture-validation.sh runs",
    ),
    "scripts/capture-validation/zenoh-workload.sh": (
        "one zenoh workload of the validation corpus, run inside the capture container",
        "runs whenever scripts/capture-validation.sh runs",
    ),
    "scripts/gc-build-artifacts.sh": (
        "garbage collection of a build host's target directory; the pre-push hook runs its "
        "installed-toolchain mode where cargo-sweep is present",
        "runs on a push through the pre-push hook, and by hand around a full run-ci.sh",
    ),
    "scripts/install-mnemosyne-mcp.sh": (
        "installs the store's MCP server for agent sessions; no lane speaks MCP",
        "run by hand when the store tool pin moves (CLAUDE.md, the stale MCP server)",
    ),
    "scripts/install-shellcheck.sh": (
        "installs the pinned shellcheck on a developer or fleet machine; hosted runners "
        "carry their own",
        "run by bx as the shellcheck tool's install (bx.toml), and by hand",
    ),
    "scripts/kit-size-delta.sh": (
        "builds kit images in a base tree and this one on a build machine; its reader "
        "kit_size_delta.py is selftested in Layer C0",
        "run through bx with the kit-size-delta label when a kit image's size is attributed",
    ),
    "scripts/land.sh": (
        "submits a session's commits to the landing queue, which pushes; no lane may",
        "run by hand by every session that lands on main",
    ),
    "scripts/lib/artifact-root-bin/cargo": (
        "the cargo that artifact-root.sh puts first on PATH when WZ_ARTIFACT_ROOT is set; "
        "a program reached through PATH is not read here",
        "runs on every cargo call of a lane or tool started with WZ_ARTIFACT_ROOT set",
    ),
    "scripts/lib/image_top_report.py": (
        "prints a built image's largest frames and symbols for a person to diff; needs the "
        "image and the arm binutils",
        "run by hand on two built images when a kit regression is attributed",
    ),
    "scripts/lib/pc_profile.py": (
        "maps a kit profile run's program-counter samples to functions; needs a profile run "
        "on the kit",
        "run by hand on the samples kit-lane.sh writes with KIT_PROFILE_OUT set",
    ),
    "scripts/lib/previous-run-gate.sh": (
        "reads the previous hosted run's verdict; the pre-push hook sources it (gate 2c)",
        "runs on every push through the pre-push hook",
    ),
    "scripts/lib/schema-pin-gate.sh": (
        "the store schema pin gate, sourced by the pre-commit and pre-push hooks",
        "runs on every commit and every push through the hooks",
    ),
    "scripts/lib/test_build_size.sh": (
        "measures one crate's test build into a fresh target directory, before and after a "
        "merge of its test executables",
        "run by hand on one host around a merge_tests.py move",
    ),
    "scripts/lib/workspace-check-gate.sh": (
        "the workspace type-check of the pre-push hook; the lanes build the crates themselves",
        "runs on every push through the pre-push hook",
    ),
    "scripts/pico-compare.sh": (
        "the host performance comparison with zenoh-pico; needs idle pinned CPUs on a build "
        "host, and the tools it runs (perf_matrix.py, nodrop.py, parity.py) are reached by a "
        "Layer C0 selftest leg",
        "run through bx on the performance host (docs/pico-perf-matrix.md)",
    ),
    "scripts/provision-zephyr.sh": (
        "provisions the Zephyr workspace and SDK at the pins ci.yml states; the hosted jobs "
        "provision with steps of their own",
        "run by bx as the zephyr tools' install (bx.toml), and by hand with --check",
    ),
    "scripts/qnx-toolchain-env.sh": (
        "sourced at a QNX SDP the caller provides; no lane has one",
        "sourced by hand, or through scripts/with-sdk-env.sh, on a machine with the SDP",
    ),
    "scripts/regen-calibration.sh": (
        "regenerates the calibration module from the capture corpus; a crate test of the lanes "
        "checks that the committed module is current",
        "run by hand after a capture is added to captures/corpus/",
    ),
    "scripts/regen-codegen.sh": (
        "regenerates the committed out/ tree, which a lane must not write; Layer B2 checks "
        "that the committed tree is current",
        "run by the main session as the regen-codegen action (bx.toml)",
    ),
    "scripts/round-runner.sh": (
        "drives one debt round per agent session on the operator's machine",
        "run by hand by the operator",
    ),
    "scripts/sweep-target.sh": (
        "reaps the build artefacts no gate touches from a checkout's target directory",
        "run by hand, and by scripts/round-runner.sh between rounds",
    ),
    "scripts/with-sdk-env.sh": (
        "runs one command inside a Yocto or QNX SDK the caller provides; no lane has one",
        "run by hand, or by a build machine's job, where the SDK is",
    ),
    "scripts/yocto-toolchain-env.sh": (
        "sourced at a Yocto SDK the caller provides; no lane has one",
        "sourced by hand, or through scripts/with-sdk-env.sh, on a machine with the SDK",
    ),
}

# ── the population ────────────────────────────────────────────────────────────


def is_script(rel: str, text: str) -> bool:
    """A python or shell script by name, or an executable script by its shebang."""
    return rel.endswith((".py", ".sh")) or text.startswith("#!")


def left_out(rel: str, text: str) -> bool:
    """Vendored by its path, or generated by its header."""
    if VENDORED_SEGMENTS.intersection(rel.split("/")):
        return True
    return any(GENERATED_HEADER.match(line) for line in text.split("\n")[:HEAD_LINES])


def population(files: dict[str, str]) -> list[str]:
    """The scripts under scripts/ that are graded, sorted."""
    return sorted(
        rel
        for rel, text in files.items()
        if rel.startswith(SCRIPTS) and is_script(rel, text) and not left_out(rel, text)
    )


def lane_roots(paths) -> list[str]:
    """run-ci.sh, the workflows and the composite actions, of the paths given."""
    out = [RUN_CI] if RUN_CI in paths else []
    for rel in sorted(paths):
        top_level = "/" not in rel[len(WORKFLOWS) :]
        if rel.startswith(WORKFLOWS) and rel.endswith(YAML_SUFFIX) and top_level:
            out.append(rel)
        elif rel.startswith(ACTIONS) and posixpath.basename(rel) in ACTION_NAMES:
            out.append(rel)
    return out


# ── what is shell code ────────────────────────────────────────────────────────

_CODE_LIKE = frozenset({"code", "sub", "bt"})
_HEREDOC = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


def shell_mask(text: str) -> list[bool]:
    """For each character of a shell text: True when it is code.

    Not code: a single- or double-quoted string, a comment, a heredoc body. Code again: a
    command substitution or a backquote inside a double-quoted string. One pass over the
    whole text, because a double-quoted message may run over several lines.
    """
    n = len(text)
    mask = [False] * n
    stack = ["code"]
    pending: list[tuple[bool, str]] = []
    i = 0
    while i < n:
        c = text[i]
        top = stack[-1]
        code = top in _CODE_LIKE
        if c == "\n":
            mask[i] = code
            i += 1
            if pending and code:
                for strip_tabs, delimiter in pending:
                    while i < n:
                        end = text.find("\n", i)
                        if end < 0:
                            end = n
                        line = text[i:end]
                        i = end + 1
                        if (line.lstrip("\t") if strip_tabs else line).strip() == delimiter:
                            break
                pending = []
            continue
        mask[i] = code
        if top == "sq":
            if c == "'":
                stack.pop()
            i += 1
            continue
        if top == "dq":
            if c == "\\":
                i += 2
            elif c == '"':
                stack.pop()
                i += 1
            elif c == "$" and text.startswith("(", i + 1):
                stack.append("sub")
                i += 2
            elif c == "`":
                stack.append("bt")
                i += 1
            else:
                i += 1
            continue
        if c == "\\":
            i += 2
        elif c == "'":
            stack.append("sq")
            i += 1
        elif c == '"':
            stack.append("dq")
            i += 1
        elif c == "`":
            if top == "bt":
                stack.pop()
            else:
                stack.append("bt")
            i += 1
        elif c == "#" and (i == 0 or text[i - 1].isspace()):
            end = text.find("\n", i)
            if end < 0:
                end = n
            for k in range(i, end):
                mask[k] = False
            i = end
        elif c == "$" and text.startswith("(", i + 1):
            stack.append("sub")
            i += 2
        elif c == "(" and top == "sub":
            stack.append("sub")
            i += 1
        elif c == ")" and top == "sub":
            stack.pop()
            i += 1
        elif c == "<" and text.startswith("<", i + 1) and not text.startswith("<", i + 2):
            heredoc = _HEREDOC.match(text, i)
            if heredoc:
                pending.append((heredoc.group(1) == "-", heredoc.group(3)))
                i = heredoc.end()
            else:
                i += 1
        else:
            i += 1
    return mask


_RUN_KEY = re.compile(r"^(\s*(?:-\s+)?)run:(\s*)(.*)$")
_BLOCK_SCALAR = re.compile(r"^[|>][-+0-9]*\s*(?:#.*)?$")


def workflow_shell(text: str) -> str:
    """The run steps of a workflow or action as shell text, every other line blank.

    Line numbers are kept. An inline step keeps its column, with the key blanked, so its
    command stands at a line start; a block step keeps its lines.
    """
    lines = text.split("\n")
    out = [""] * len(lines)
    i = 0
    while i < len(lines):
        key = _RUN_KEY.match(lines[i])
        if not key:
            i += 1
            continue
        column = len(key.group(1))
        value = key.group(3)
        if _BLOCK_SCALAR.match(value):
            j = i + 1
            while j < len(lines):
                line = lines[j]
                if line.strip():
                    if len(line) - len(line.lstrip()) <= column:
                        break
                    out[j] = line
                j += 1
            i = j
            continue
        out[i] = " " * (column + 4 + len(key.group(2))) + value
        i += 1
    return "\n".join(out)


# ── what is an invocation ─────────────────────────────────────────────────────

_INTERPRETER = r"(?<![\w.-])(?:python3?(?:\.\d+)?|bash|sh|source|exec)(?:\s+-[A-Za-z]+)*\s+"
_COMMAND = (
    r"(?:(?P<bol>^\s*)|[;&|]\s*|\$\(\s*|!\s+|\b(?:then|do|else)\s+|=\(\s*)"
    r"(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*(?:\.\s+)?"
    r"(?:\"?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\"?\s+)?"
)
_ASSIGNED = r"\b[A-Za-z_][A-Za-z0-9_]*="
_PATH = (
    r"[\"']?(?P<path>"
    r"(?:\"?\$\(\s*dirname\s+\"?\$\{?[A-Za-z0-9_\[\]#@]+\}?\"?\s*\)\"?)?"
    r"(?:[^\s\"'()<>|;&`]*/)?[A-Za-z0-9_.-]+\.(?:py|sh))\b"
)
INVOCATION = re.compile("(?:" + _INTERPRETER + "|" + _COMMAND + "|" + _ASSIGNED + ")" + _PATH)
SELFTEST_FLAG = re.compile(r"(?:^|\s)--selftest\b")
_COMMAND_END = re.compile(r"[;|&)]")


class Invocation(NamedTuple):
    target: str
    line: int
    selftest: bool


def resolve(token: str, src: str, known: set[str]) -> str | None:
    """The script a path token names, by its literal tail, or None."""
    if ")" in token:
        token = token[token.rindex(")") + 1 :]
    tail: list[str] = []
    for segment in reversed(token.split("/")):
        if segment in ("", ".", "..") or "$" in segment or '"' in segment or "'" in segment:
            break
        tail.insert(0, segment)
    if not tail:
        return None
    suffix = "/".join(tail)
    candidates = [p for p in known if p == suffix or p.endswith("/" + suffix)]
    if len(candidates) == 1:
        return candidates[0]
    local = posixpath.join(posixpath.dirname(src), suffix)
    return local if local in candidates else None


def invocations(text: str, src: str, known: set[str]) -> list[Invocation]:
    """The scripts a shell text, or a workflow's run steps, invoke."""
    if src.endswith(YAML_SUFFIX):
        text = workflow_shell(text)
    mask = shell_mask(text)
    lines = text.split("\n")
    out: list[Invocation] = []
    offset = 0
    continued = False
    for number, line in enumerate(lines):
        for m in INVOCATION.finditer(line):
            if not mask[offset + m.start()]:
                continue
            if m.group("bol") is not None and continued:
                continue
            target = resolve(m.group("path"), src, known)
            if target is None or target == src:
                continue
            rest = line[m.end() :]
            k = number
            while rest.endswith("\\") and k + 1 < len(lines):
                k += 1
                rest = rest[:-1] + " " + lines[k]
            command = _COMMAND_END.split(rest, maxsplit=1)[0]
            out.append(Invocation(target, number + 1, bool(SELFTEST_FLAG.search(command))))
        continued = line.endswith("\\") and mask[offset + len(line) - 1]
        offset += len(line) + 1
    return out


def python_imports(text: str, src: str, known: set[str]) -> set[str]:
    """The scripts a python script imports: its own directory first, then scripts/lib."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    here = posixpath.dirname(src)
    out: set[str] = set()
    for name in names:
        for candidate in (posixpath.join(here, name + ".py"), LIB + name + ".py"):
            if candidate in known and candidate != src:
                out.add(candidate)
                break
    return out


def python_calls(text: str, src: str, by_name: dict[str, str]) -> set[str]:
    """The scripts a python script runs through subprocess, by a name only one script has."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        named = round_fed_gate_reach.module_invocations(text, set(by_name))
    return {by_name[name] for name in named if by_name[name] != src}


def unique_names(scripts: list[str]) -> dict[str, str]:
    seen: dict[str, list[str]] = {}
    for rel in scripts:
        seen.setdefault(posixpath.basename(rel), []).append(rel)
    return {name: rels[0] for name, rels in seen.items() if len(rels) == 1}


# ── the classes ───────────────────────────────────────────────────────────────


def classify(
    files: dict[str, str], scripts: list[str], roots: list[str]
) -> dict[str, tuple[str, str]]:
    """script -> (class, where it was reached). Pure over the texts it is handed."""
    known = set(scripts)
    # A bare program name in a subprocess call is a PATH lookup, not a script path: only a name
    # with a script's suffix is read, as the shell reader reads only those.
    by_name = unique_names([rel for rel in scripts if rel.endswith((".py", ".sh"))])
    run: dict[str, str] = {}
    selftested: dict[str, str] = {}
    run_queue: list[str] = []
    selftest_queue: list[str] = []

    def follow(src: str, selftest_only: bool) -> None:
        for inv in invocations(files.get(src, ""), src, known):
            if selftest_only and not inv.selftest:
                continue
            where = f"{src}:{inv.line}"
            if inv.selftest:
                if inv.target not in selftested:
                    selftested[inv.target] = where
                    selftest_queue.append(inv.target)
            elif inv.target not in run:
                run[inv.target] = where
                run_queue.append(inv.target)

    for root in roots:
        if root in known:
            run.setdefault(root, "a lane root")
            run_queue.append(root)
        else:
            follow(root, False)

    run_done: set[str] = set()
    selftest_done: set[str] = set()
    while run_queue or selftest_queue:
        while run_queue:
            src = run_queue.pop(0)
            if src in run_done:
                continue
            run_done.add(src)
            if src.endswith(".py"):
                for target in sorted(python_calls(files.get(src, ""), src, by_name)):
                    if target not in run:
                        run[target] = f"{src} (a subprocess call)"
                        run_queue.append(target)
            else:
                follow(src, False)
        while selftest_queue:
            src = selftest_queue.pop(0)
            if src in selftest_done:
                continue
            selftest_done.add(src)
            if not src.endswith(".py"):
                follow(src, True)

    imported: dict[str, str] = {}
    frontier = [rel for rel in list(run) + list(selftested) if rel.endswith(".py")]
    seen = set(frontier)
    while frontier:
        src = frontier.pop(0)
        for target in sorted(python_imports(files.get(src, ""), src, known)):
            imported.setdefault(target, src)
            if target not in seen:
                seen.add(target)
                frontier.append(target)

    out: dict[str, tuple[str, str]] = {}
    for rel in scripts:
        if rel in run:
            out[rel] = (RUN, run[rel])
        elif rel in selftested:
            out[rel] = (SELFTESTED, selftested[rel])
        elif rel in imported:
            out[rel] = (IMPORTED, f"imported by {imported[rel]}")
        else:
            out[rel] = (UNCLASSIFIED, "")
    return out


def with_declared(classes: dict[str, tuple[str, str]], declared) -> dict[str, tuple[str, str]]:
    """The classes with a DECLARED row's script, when no lane reaches it, named DECLARED."""
    out = dict(classes)
    for rel, (cls, _) in classes.items():
        if cls == UNCLASSIFIED and rel in declared:
            out[rel] = (DECLARED_CLASS, declared[rel][1])
    return out


def findings(classes: dict[str, tuple[str, str]], declared, roots: list[str]) -> list[str]:
    """What fails --check. Pure over the classes, the table and the roots."""
    out: list[str] = []
    if not classes:
        out.append(
            "the population is empty: no script under scripts/ was read, so every statement "
            "below would hold of nothing."
        )
        return out
    reached = any(cls == RUN and via != "a lane root" for cls, via in classes.values())
    if RUN_CI not in roots or not reached:
        out.append(
            "no lane invocation was read: scripts/run-ci.sh is missing or the reader matched none "
            "of its lines, so the classes below grade nothing."
        )
    for rel, (cls, _) in sorted(classes.items()):
        if cls == UNCLASSIFIED and rel not in declared:
            out.append(
                f"{rel} is exercised by no lane: it is not RUN (no non-comment line of "
                f"scripts/run-ci.sh, of a workflow or action run step, or of a RUN script "
                f"invokes it), not SELFTESTED (no lane runs its --selftest), not IMPORTED (no "
                f"RUN or SELFTESTED python script imports it) and not DECLARED. Enter one: run "
                f"it from a lane, add a Layer C0 leg that runs its --selftest, import it from a "
                f"script a lane exercises, or add a DECLARED row in "
                f"scripts/lib/script_exercise_census.py with the reason no lane runs it and the "
                f"owner action that does."
            )
    for rel, row in sorted(declared.items()):
        reason, action = row
        if not reason.strip():
            out.append(f"the DECLARED row of {rel} has no reason; a row is a reason, or it goes.")
        if not action.strip():
            out.append(f"the DECLARED row of {rel} names no owner action that exercises it.")
        if rel not in classes:
            out.append(
                f"the DECLARED row of {rel} names no script of the population (moved, removed "
                f"or left out by rule): drop the row."
            )
        elif classes[rel][0] != UNCLASSIFIED:
            cls, via = classes[rel]
            out.append(
                f"the DECLARED row of {rel} is stale: the script is {cls} ({via}). Drop the row."
            )
    return out


def counts(classes: dict[str, tuple[str, str]]) -> dict[str, int]:
    out = {cls: 0 for cls in CLASS_ORDER}
    for cls, _ in classes.values():
        out[cls] += 1
    return out


def summary(classes: dict[str, tuple[str, str]]) -> str:
    n = counts(classes)
    parts = ", ".join(f"{n[cls]} {cls}" for cls in CLASS_ORDER)
    return f"script-exercise-census: {len(classes)} script(s): {parts}"


# ── the tree ──────────────────────────────────────────────────────────────────


def tracked(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=False
    )
    return [p for p in out.stdout.split("\n") if p]


def read_tree(root: Path, paths: list[str]) -> dict[str, str]:
    """The texts this census reads: scripts/, the workflows and the actions."""
    out: dict[str, str] = {}
    wanted = set(lane_roots(paths))
    for rel in paths:
        if not (rel.startswith(SCRIPTS) or rel in wanted):
            continue
        path = root / rel
        if path.is_file():
            out[rel] = path.read_text(errors="replace")
    return out


def judge(files: dict[str, str], declared) -> tuple[dict[str, tuple[str, str]], list[str]]:
    scripts = population(files)
    roots = lane_roots(files)
    classes = classify(files, scripts, roots)
    return with_declared(classes, declared), findings(classes, declared, roots)


def check(root: Path, report: bool) -> int:
    paths = tracked(root)
    if not paths:
        print("script-exercise-census: FAIL -- git ls-files named no file", file=sys.stderr)
        return 1
    classes, problems = judge(read_tree(root, paths), DECLARED)
    print(summary(classes))
    if report:
        for rel, (cls, via) in sorted(classes.items()):
            print(f"  {cls:<12} {rel}" + (f"  <- {via}" if via else ""))
    if problems:
        print("script-exercise-census: FAIL", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("script-exercise-census: OK")
    return 0


# ── selftest ──────────────────────────────────────────────────────────────────

_FIXTURE_RUN_CI = (
    "#!/usr/bin/env bash\n"
    "# python3 scripts/lib/commented.py\n"
    "layer_c0() {\n"
    "    _runci_legs_open C0 || return 1\n"
    "    _runci_leg a -- python3 scripts/lib/a.py\n"
    "    _runci_leg b.selftest -- python3 scripts/lib/b.py --selftest\n"
    "    _runci_leg both.selftest -- python3 scripts/lib/both.py --selftest\n"
    "    _runci_leg both --after both.selftest -- python3 scripts/lib/both.py --check\n"
    "    _runci_leg h.selftest -- bash scripts/h.sh --selftest\n"
    "    bash scripts/c.sh\n"
    '    local script="scripts/lib/d.sh"\n'
    '    out="$(python3 -I scripts/lib/subst.py --list)"\n'
    '    echo "  provision it with: bash scripts/lib/echoed.sh" >&2\n'
    '    echo "a message that runs over" \\\n'
    '        "two lines: bash scripts/lib/continued.sh" >&2\n'
    '    echo "a message over two lines\n'
    '  scripts/lib/multiline.sh is named in it"\n'
    "    git diff --quiet -- \\\n"
    "        'scripts/lib/argument.sh' 2>/dev/null\n"
    "    cat >\"$x\" <<'EOF'\n"
    "python3 scripts/lib/heredoc.py\n"
    "EOF\n"
    "    awk '\n"
    "        python3 scripts/lib/awk.py\n"
    "    ' \"$f\"\n"
    "    bash dup.sh\n"
    "    cp x.sh scripts/lib/copied.sh\n"
    "    _runci_legs_close\n"
    "}\n"
)

_FIXTURE: dict[str, str] = {
    RUN_CI: _FIXTURE_RUN_CI,
    "scripts/c.sh": (
        "#!/usr/bin/env bash\n"
        'source "$(dirname "${BASH_SOURCE[0]}")/lib/e.sh"\n'
        'HERE="$(cd "$(dirname "$0")" && pwd)"\n'
        'bash "$HERE/one/caller.sh"\n'
    ),
    "scripts/one/caller.sh": 'HERE="$(cd "$(dirname "$0")" && pwd)"\nbash "$HERE/dup.sh"\n',
    "scripts/one/dup.sh": "true\n",
    "scripts/two/dup.sh": "true\n",
    "scripts/h.sh": (
        "#!/usr/bin/env bash\n"
        'here="scripts/sub"\n'
        'py="$(command -v python3)"\n'
        'if [ "${1:-}" = "--selftest" ]; then\n'
        '    "$py" "$here/i.py" --selftest\n'
        "    exit $?\n"
        "fi\n"
        '"$py" "$here/j.py" prepare\n'
    ),
    "scripts/sub/i.py": "pass\n",
    "scripts/sub/j.py": "pass\n",
    "scripts/lib/a.py": (
        "import subprocess\n"
        "import k\n"
        "from pathlib import Path\n"
        "ROOT = Path(__file__).resolve().parents[2]\n"
        'TOOL = ROOT / "scripts" / "lib" / "called.sh"\n'
        'NAMED = "scripts/lib/named.sh"\n'
        'subprocess.run(["bash", str(TOOL)], check=False)\n'
        'subprocess.run(["tool", "--version"], check=False)\n'
    ),
    "scripts/lib/k.py": "from l import x\n",
    "scripts/lib/l.py": "x = 1\n",
    "scripts/lib/b.py": "import m\n",
    "scripts/lib/m.py": "pass\n",
    "scripts/lib/orphan.py": "import n\n",
    "scripts/lib/n.py": "pass\n",
    "scripts/lib/both.py": "pass\n",
    "scripts/lib/called.sh": "true\n",
    "scripts/lib/named.sh": "true\n",
    "scripts/lib/d.sh": "true\n",
    "scripts/lib/e.sh": "true\n",
    "scripts/lib/subst.py": "pass\n",
    "scripts/inline.sh": "true\n",
    "scripts/lib/block.py": "pass\n",
    "scripts/action.sh": "true\n",
    "scripts/lib/commented.py": "pass\n",
    "scripts/lib/echoed.sh": "true\n",
    "scripts/lib/continued.sh": "true\n",
    "scripts/lib/multiline.sh": "true\n",
    "scripts/lib/argument.sh": "true\n",
    "scripts/lib/heredoc.py": "pass\n",
    "scripts/lib/awk.py": "pass\n",
    "scripts/lib/pathsonly.py": "pass\n",
    "scripts/lib/sparse.py": "pass\n",
    "scripts/lib/hashed.sh": "true\n",
    "scripts/lib/copied.sh": "true\n",
    "scripts/lib/bin/tool": "#!/bin/sh\ntrue\n",
    "scripts/lib/data.txt": "not a script\n",
    "scripts/vendor/v.sh": "true\n",
    "scripts/lib/gen.py": "# GENERATED by scripts/lib/a.py -- never edited by hand\nX = 1\n",
    "crates/outside.sh": "true\n",
    ".github/workflows/w.yml": (
        "on:\n"
        "  push:\n"
        "    paths:\n"
        '      - "scripts/lib/pathsonly.py"\n'
        "jobs:\n"
        "  x:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          sparse-checkout: |\n"
        "            scripts/lib/sparse.py\n"
        "      - run: bash scripts/inline.sh\n"
        "      - name: block\n"
        "        run: |\n"
        "          python3 scripts/lib/block.py --check\n"
        "        env:\n"
        "          KEY: ${{ hashFiles('scripts/lib/hashed.sh') }}\n"
    ),
    ".github/actions/x/action.yml": (
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - shell: bash\n"
        "      run: bash scripts/action.sh\n"
    ),
}

_EXPECT = {
    RUN: (
        RUN_CI,
        "scripts/lib/a.py",
        "scripts/lib/both.py",
        "scripts/c.sh",
        "scripts/lib/e.sh",
        "scripts/one/caller.sh",
        "scripts/one/dup.sh",
        "scripts/lib/d.sh",
        "scripts/lib/subst.py",
        "scripts/lib/called.sh",
        "scripts/inline.sh",
        "scripts/lib/block.py",
        "scripts/action.sh",
    ),
    SELFTESTED: ("scripts/lib/b.py", "scripts/h.sh", "scripts/sub/i.py"),
    IMPORTED: ("scripts/lib/k.py", "scripts/lib/l.py", "scripts/lib/m.py"),
    DECLARED_CLASS: (
        "scripts/lib/commented.py",
        "scripts/lib/echoed.sh",
        "scripts/lib/continued.sh",
    ),
    UNCLASSIFIED: (
        "scripts/lib/multiline.sh",
        "scripts/lib/argument.sh",
        "scripts/lib/heredoc.py",
        "scripts/lib/awk.py",
        "scripts/lib/pathsonly.py",
        "scripts/lib/sparse.py",
        "scripts/lib/hashed.sh",
        "scripts/lib/copied.sh",
        "scripts/lib/named.sh",
        "scripts/sub/j.py",
        "scripts/two/dup.sh",
        "scripts/lib/orphan.py",
        "scripts/lib/n.py",
        "scripts/lib/bin/tool",
    ),
}

_FIXTURE_DECLARED = {
    "scripts/lib/commented.py": ("a reason", "an action"),
    "scripts/lib/echoed.sh": ("", "an action"),
    "scripts/lib/continued.sh": ("a reason", "  "),
    "scripts/lib/gone.sh": ("a reason", "an action"),
    "scripts/lib/a.py": ("a reason", "an action"),
    "scripts/lib/gen.py": ("a reason", "an action"),
}


def selftest() -> int:
    failed = 0
    total = 0

    def arm(label: str, ok: bool) -> None:
        nonlocal failed, total
        total += 1
        print(f"  [{'ok' if ok else 'FAIL'}] {label}")
        if not ok:
            failed += 1

    classes, problems = judge(_FIXTURE, _FIXTURE_DECLARED)
    for want, paths in _EXPECT.items():
        for rel in paths:
            got = classes.get(rel, ("left out", ""))[0]
            arm(f"{rel} is {want} (got {got})", got == want)
    left_out_paths = (
        "scripts/vendor/v.sh",
        "scripts/lib/gen.py",
        "scripts/lib/data.txt",
        "crates/outside.sh",
    )
    for rel in left_out_paths:
        arm(f"{rel} is left out of the population", rel not in classes)
    expected = sum(len(paths) for paths in _EXPECT.values())
    arm(f"the population is exactly the {expected} scripts named", len(classes) == expected)
    arm("every class is reached by the fixture", all(counts(classes)[cls] for cls in CLASS_ORDER))

    def finds(text: str) -> bool:
        return any(text in problem for problem in problems)

    for rel in _EXPECT[UNCLASSIFIED]:
        arm(f"{rel}, in no class and no row, fails", finds(f"{rel} is exercised by no lane"))
    arm("a declared script does not fail", not finds("scripts/lib/commented.py is exercised"))
    arm("a row with a blank reason fails", finds("scripts/lib/echoed.sh has no reason"))
    arm("a row with a blank action fails", finds("scripts/lib/continued.sh names no owner action"))
    arm("a row of a removed script fails", finds("scripts/lib/gone.sh names no script"))
    arm("a row of a script left out by rule fails", finds("scripts/lib/gen.py names no script"))
    arm("a row of a RUN script is stale", finds("scripts/lib/a.py is stale"))
    arm("a tree with lanes does not fail as unread", not finds("no lane invocation was read"))
    expected_problems = len(_EXPECT[UNCLASSIFIED]) + 5
    arm(f"exactly {expected_problems} findings", len(problems) == expected_problems)

    without_lanes = {rel: text for rel, text in _FIXTURE.items() if rel == "scripts/lib/a.py"}
    arm("a tree without run-ci.sh fails as unread", any(
        "no lane invocation was read" in p for p in judge(without_lanes, {})[1]))
    arm("an empty tree fails", any("population is empty" in p for p in judge({}, {})[1]))
    arm("every DECLARED row of this tree has both strings", all(
        reason.strip() and action.strip() for reason, action in DECLARED.values()))

    print(f"script-exercise-census selftest: {total - failed}/{total} arm(s) pass")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="every script under scripts/ is exercised by a lane, or declared"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail on a script in no class")
    mode.add_argument(
        "--report", action="store_true", help="the check, with each script's class and source"
    )
    mode.add_argument("--selftest", action="store_true", help="drive the rule on synthetic trees")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    return check(ROOT, report=args.report)


if __name__ == "__main__":
    raise SystemExit(main())
