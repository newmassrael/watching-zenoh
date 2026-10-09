#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2167 (no register item) — what a count guard's command IS, once the shell has
assembled it. Answers for open-debt item 787, which lives in the agent-memory
register and has no store id for `gate_provenance_lint.py` to resolve; the gate
it serves cites R2167 the same way.

`guarded_count_gate.py` runs the count guards a push can move. A guard whose
command the shell assembles (`--features "$ML_DEPLOY_FEATURES"`, `--exact
"$leg"` inside a `for`, `env WZ_ZENOHD_BIN="$zenohd"`) was DEFERRED: 51 of 435
at the time of writing, and "only the hosted lane measures these" is exactly
the hole the gate exists to close. The first answer to it (R2650) was to
substitute the variables that are assigned ONE literal. That is a reader of the
shell's text, and it stops at the first loop or the first concatenation.

This module asks the shell itself. It builds a copy of `run-ci.sh` that keeps
only the function definitions (same line numbers, every other line blank), runs
the lane function that holds a guard in a bash whose external commands are all
absent, and records what `_runci_guarded_test` (and a bare `cargo`) was CALLED
WITH. Bash expands the variables, runs the loops and joins the strings; this
file only reads the result back.

## What makes that safe to believe

A command this cannot reproduce must stay deferred rather than become
measurable and WRONG, so a recorded call is accepted only when it matches the
static line it came from:

  * the recorded argv has as many words as the line's own tokens;
  * every word the line writes without `$`, a backtick or a quote is identical;
  * every word with an expansion matches the line's word read as a template, each
    variable standing for at least one character. A `features` list that came
    out empty because `$(python3 ...)` produced nothing in a bash that has no
    python is exactly this case, and is refused. The one exception is the VALUE
    of an `env NAME=...` assignment: those carry hosted-only paths (a `zenohd`
    binary), are empty here by construction, and the gate never uses them;
  * a word built from a command substitution is refused outright.

The sandbox runs in an empty directory with a bare environment, so a lane that
writes a file writes it there, and a variable the developer's shell exports
cannot leak into a resolved command.

## What the sandbox assumes, stated

Three rewrites are made to the SANDBOX'S COPY of the lane under test, never to
`run-ci.sh`:

  * `return` and `exit` become no-ops, so an early bail-out for a missing binary
    does not hide the guards after it;
  * a condition that is nothing but a file test (`[[ -x "$dir/tool" ]]`, with
    or without `!`) answers "present". A lane reaches its guards only on a
    machine that has the input, which is the hosted one; a developer machine
    that lacks it would otherwise make the command shape unobservable. Compound
    conditions are left alone;
  * a line that is nothing but one `NAME=literal` assignment at top level of
    `run-ci.sh` is kept (`EWIREZ_WITNESS_BUDGET="${EWIREZ_WITNESS_BUDGET:-180}"`);
    every other top-level line is blanked.

## What it cannot do, stated

Control flow decides which guards are reached. A loop over `$(command)` iterates
over nothing here, and a guard inside it is reported unreached. That guard stays
DEFERRED with the reason, never silently dropped.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

FN_OPEN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) \{")

# How long one lane may run. Lanes in the sandbox do nothing slow, so a lane
# that reaches this is spinning on a condition its missing commands can never
# change; what it recorded before then is still read.
LANE_TIMEOUT_S = 30

RETURN_RE = re.compile(
    r"\b(?:return|exit)\b(?:[ \t]+(?:[0-9]+|\$\{?[A-Za-z_?][A-Za-z0-9_]*\}?))?"
)

TOP_ASSIGN_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*="
    r"(?:\"(?:[^\"`$]|\$(?!\())*\"|'[^']*'|[^\s\"'`$();|&<>]*)[ \t]*(?:#.*)?$"
)

# `[[ -x "$dir/tool" ]]` and its siblings, when the test is the WHOLE condition.
# The lane asks whether an input a developer machine may lack (a built `zenohd`,
# an examples directory) is there, and skips its guards when it is not. The
# guards are only reached on a machine that has the input, which is the hosted
# one, so the sandbox answers "present": a command shape that exists only behind
# a file test is otherwise unobservable. Only the sandbox's COPY is rewritten.
FILE_TEST_RE = re.compile(
    r"\[\[[ \t]+(!?)[ \t]*-[xfesdrwLhk][ \t]+"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s\]]+)[ \t]+\]\]"
)

# Expansions inside one shell word. `$(...)` and backticks are refused; plain
# `$name` / `${name}` are templates.
CMD_SUBST_RE = re.compile(r"\$\(|`")
VAR_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*")
ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def functions(text):
    """`[(name, first_line, last_line)]`, 1-based and inclusive, for every
    column-0 `name() {` ... column-0 `}` block."""
    out = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        m = FN_OPEN_RE.match(lines[i])
        if not m:
            i += 1
            continue
        j = i + 1
        while j < len(lines) and lines[j] != "}":
            j += 1
        if j < len(lines):
            out.append((m.group(1), i + 1, j + 1))
        i = j + 1
    return out


def enclosing(fns, lineno):
    for name, lo, hi in fns:
        if lo <= lineno <= hi:
            return name
    return None


def functions_only_source(text, fns, neutralise):
    """A copy of `text` with the same line count in which every line outside a
    function definition is blank, so a recorded line number is `run-ci.sh`'s own.

    `neutralise` names the functions whose `return`/`exit` become no-ops.
    """
    lines = text.split("\n")
    out = [""] * len(lines)
    # A lane reads a few settings the script assigns at top level
    # (`EWIREZ_WITNESS_BUDGET="${EWIREZ_WITNESS_BUDGET:-180}"`). A line that is
    # nothing but one such assignment is kept; anything else outside a function
    # (the dispatch, the checkpoint file, the traps) is not.
    for k, ln in enumerate(lines):
        if TOP_ASSIGN_RE.match(ln):
            out[k] = ln
    for name, lo, hi in fns:
        for k in range(lo - 1, hi):
            ln = lines[k]
            if name in neutralise and not ln.lstrip().startswith("#"):
                ln = RETURN_RE.sub(":", ln)
                ln = FILE_TEST_RE.sub(
                    lambda m: "false" if m.group(1) else "true", ln
                )
            out[k] = ln
    return "\n".join(out)


# `cd` and `set` are builtins that can end the sandbox early or change how the
# rest of it behaves (`set -u` turns an unset variable into a hard stop), so
# they are shadowed with functions. `exec` and `source` could replace or extend
# the process. Every command that is not a builtin or a function is absent
# (PATH points nowhere) and `command_not_found_handle` makes its absence a
# silent success, which is what lets a lane keep running.
HARNESS = r"""
exec 9>"$REC_FILE"
exec </dev/null
source "$FUNCS_FILE"
__rec() { printf '%s\0' "$@" >&9; }
_runci_guarded_test() { __rec helper "${BASH_LINENO[0]}" "$#" "$@"; return 0; }
cargo() { __rec cargo "${BASH_LINENO[0]}" "$#" "$@"; return 0; }
command_not_found_handle() { return 0; }
cd() { return 0; }
pushd() { return 0; }
popd() { return 0; }
set() { return 0; }
exec() { return 0; }
source() { return 0; }
PATH=/nonexistent
"$LANE_FN"
"""


class Call:
    """One recorded invocation: `kind` is `helper` (`_runci_guarded_test`) or
    `cargo`; `args` is the argv bash passed after expansion."""

    def __init__(self, kind, line, args):
        self.kind = kind
        self.line = line
        self.args = args

    def __repr__(self):
        return f"Call({self.kind}, {self.line}, {self.args!r})"


def parse_records(blob):
    parts = blob.split(b"\0")
    calls = []
    i = 0
    while i + 2 < len(parts):
        kind = parts[i].decode("utf-8", "surrogateescape")
        try:
            line = int(parts[i + 1])
            n = int(parts[i + 2])
        except ValueError:
            break
        args = parts[i + 3 : i + 3 + n]
        if len(args) < n:
            break  # a record cut by the timeout
        calls.append(
            Call(kind, line, [a.decode("utf-8", "surrogateescape") for a in args])
        )
        i += 3 + n
    return calls


def record_lane(text, fns, lane, bash="/bin/bash"):
    """Every call the lane function `lane` makes to the helper or to cargo, as
    bash expanded them. `None` when the sandbox itself could not start."""
    src = functions_only_source(text, fns, {lane})
    with tempfile.TemporaryDirectory(prefix="wz-guard-shell-") as tmp:
        funcs = Path(tmp) / "funcs.sh"
        rec = Path(tmp) / "rec.bin"
        harness = Path(tmp) / "harness.sh"
        funcs.write_text(src)
        harness.write_text(HARNESS)
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": tmp,
            "LC_ALL": "C",
            "REC_FILE": str(rec),
            "FUNCS_FILE": str(funcs),
            "LANE_FN": lane,
        }
        try:
            subprocess.run(
                [bash, str(harness)],
                cwd=tmp,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=LANE_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            pass  # keep what was recorded before the lane spun
        except OSError:
            return None
        try:
            return parse_records(rec.read_bytes())
        except OSError:
            return None


def lane_calls(text, linenos):
    """`{lane function name: [Call]}` for every lane that holds one of `linenos`.

    Each lane runs once. A line with no enclosing function (top-level code in
    `run-ci.sh`) is simply absent from the answer.
    """
    fns = functions(text)
    lanes = {}
    for ln in sorted(set(linenos)):
        name = enclosing(fns, ln)
        if name:
            lanes.setdefault(name, None)
    for name in lanes:
        lanes[name] = record_lane(text, fns, name)
    return lanes


def _unquote(word):
    return word.replace('"', "").replace("'", "")


def template_regex(word):
    """The line's word read as a template, or `None` when it cannot be one."""
    if CMD_SUBST_RE.search(word):
        return None
    w = _unquote(word)
    env = ENV_ASSIGN_RE.match(w)
    head = ""
    if env:
        head = w[: env.end()]
        w = w[env.end() :]
    pieces = VAR_RE.split(w)
    n_vars = len(VAR_RE.findall(w))
    quant = "(.*)" if env else "(.+)"
    rx = re.escape(head) if head else ""
    for k, piece in enumerate(pieces):
        rx += re.escape(piece)
        if k < n_vars:
            rx += quant
    return re.compile("^" + rx + "$", re.S)


def match_call(static_words, argv):
    """`(True, "")` when `argv` is what the static words produce, else
    `(False, reason)`."""
    if len(static_words) != len(argv):
        return False, (
            f"the shell produced {len(argv)} word(s) where the line spells "
            f"{len(static_words)}"
        )
    for word, got in zip(static_words, argv):
        if not re.search(r"[$`\"']", word):
            if word != got:
                return False, f"`{word}` came out as `{got}`"
            continue
        rx = template_regex(word)
        if rx is None:
            return False, f"`{word}` is built from a command substitution"
        if not rx.match(got):
            return False, (
                f"`{word}` came out as `{got}`, which a variable that expanded "
                "to nothing explains"
            )
    return True, ""
