#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4654 (no register item) -- D(L, t): the digest a lane's verdict is keyed by (RFC 0001, stage M1).

## Interface (fixed: the receipt store and `scripts/verify-once.sh`, stages M2 and M3, call these
## names with these signatures; a change of meaning is a new SCHEMA word)

    lanes(root, rev, *, tables=None, decls_from=None) -> list[dict]
        G(t) for the tree of `rev`: one dict per unit `bx --checks ci` runs, in the dispatch table's
        order: {"id": the unit's name ("C1nh", "Qzk:<part>"), "lane": the dispatch id, "part": the
        part or None, "class": "D" | "E" | "S", "opaque": bool, "unit": the planner's unit dict,
        whose "name" equals "id"}. `tables` overrides the planner's lane tables (a selftest's).
        With `decls_from` (see "Comparing two trees"), a unit neither tree declares is left out.
    digest(root, rev, lane_id, *, env_reader=None, decls_from=None) -> str
        D(L, t) as 64 lowercase hex digits. `lane_id` is a dispatch id or `<id>:<part>`.
    record(root, rev, lane_id, *, env_reader=None, decls_from=None) -> dict
        what the digest hashes, so an auditor recomputes it from the record alone with
        `digest_of(record)`: {"schema", "lane", "opaque", "spec", "env", "inputs"}.
    digest_of(record) -> str
    explain(root, base, head, lane_id, *, env_reader=None) -> str
        why the lane is or is not selected between two trees: equal digests, or the spec fields,
        env fields and input entries that differ.
    select(root, base, head, *, env_reader=None, tables=None) -> list[str]
        Sel (RFC 0001 5.1, the base form): the unit ids of G(head) whose digest at head differs
        from their digest at base, or that base does not have.
    parse_shell(text) -> ShellDefs
        a shell text's top-level function definitions and the code outside them, each without
        comments; ShellParseError where the text cannot be split (see "The dispatch script").
    DigestError       raised for a tree whose digest cannot be computed (no dispatch table, an
                      undeclared lane, a workflow that does not parse); never a silent default.
    GitError          (`git_tree`'s) raised for a revision git cannot read.

    python3 scripts/lib/lane_digest.py --lanes   [--rev R]                JSON lines of lanes()
    python3 scripts/lib/lane_digest.py --digest ID  [--rev R]
    python3 scripts/lib/lane_digest.py --record ID  [--rev R]             the record as JSON
    python3 scripts/lib/lane_digest.py --explain ID --base B [--head H]
    python3 scripts/lib/lane_digest.py --select --base B [--head H]       one unit id a line
    python3 scripts/lib/lane_digest.py --check      every declared lane of HEAD has a digest
    python3 scripts/lib/lane_digest.py --selftest

`--root` (default: the repository holding this file) names another checkout; R, B and H default
to HEAD and are anything `git rev-parse` reads.

## What the digest holds (RFC 0001 4.2 and 4.3)

    D(L, t) = SHA-256( len-prefixed "wz-lane-digest/2", spec, env, inputs ), each a canonical JSON
    document (sorted keys, no whitespace), each prefixed by its length in bytes.

* **spec** -- the question: the lane id, part and function; its `lanes.toml` entry; the planner's
  unit and the env and provisioning the hosted job gives it; the definitions the lane runs from
  `scripts/run-ci.sh` (`runci`, see "The dispatch script"); and the blob of every script those
  name, transitively (`scripts/...` paths, a sibling a script names, a python module it imports).
* **env** -- what the verdict depends on outside the tree: the toolchain pin's blob, the
  `[tools.*]` tables of `bx.toml`, the oracle pins (`scripts/zenoh-c-oracle.pin`, the
  `UPSTREAM_VERSION` line of `scripts/lib/upstream_feature_census.py`), and what `env_reader`
  reads from the machine: `rustc -vV` and `cargo -V` of the pinned channel, `cc --version`,
  `python3 --version`, and for an E lane alone the machine's identity (a hash of
  `/etc/machine-id`, never the value).
* **inputs** -- M(L, t): (path, mode, blob) of every tracked file in inputs(L, t), (path, commit)
  of every submodule gitlink in it, and the lock entries of the packages it builds.
  inputs(L, t) is the union of: the cargo closure (`lane_graph.py`) of every package the lane's
  cargo calls name (`-p`, `--manifest-path`, `--workspace` after a `cd` to a workspace, or a
  script's argv list of constants) and of its declared `packages` and `legs`; every tracked file
  and directory its executed lines name; its declared `decl` globs; and, when it reads the
  package graph without building (`cargo metadata`, `cargo tree`), `lane_graph.manifest_inputs`.

The time, the machine (for D and S lanes), the commit id and the branch are not in the key.

## The dispatch script

`scripts/run-ci.sh` holds every lane, so a lane's key holds the part of it the lane runs, as a build
key holds a target's own rule and not the whole build file: the code outside the functions (the
script's global setup, so a change there moves every lane), the lane's function, and every function
those name, transitively; each without its comments, the code without the other lanes' dispatch
lines (`spec.runci`: `unit` "definitions", the digest of `top` and of each of `defs`).
`parse_shell` reads the script as bash tokenizes it (quotes, `$(...)`, `${...}`, heredoc bodies and
comments are units), so no brace in a string or a heredoc ends a function. A script it sources is a
file input like any other.

The script is an input whole (`unit` "file", `why` saying why, and `--explain` printing it) when
the reader cannot split it, when the lane's function is not one it found, or when the lane reads it
as data: a script the lane runs opens it, a text the lane runs names it (another lane run whole, the
script read by a command), or a directory or a glob the lane reads holds it.

What a python script reads is read from its code. When a shell line runs it with options it spells,
and the script parses its command line once with argparse, the body of an `if args.<flag>:` whose
`store_true` option no such line passes is left out (`call_modes`, `py_options`, `_py_reached`):
every lane's `run_layer` runs `lane_decline_read.py --read`, and only Layer C0 runs its `--audit`,
which reads the whole dispatch script. A call site that may pass more than its words show (a variable
where an option could stand, the script named outside a command), a script spawned by another, or
one that could set an option some other way is read in every mode.

A module a python script imports is not run: what it reads is what importing it runs and what its
importers call (`_lib_reached`): its top-level statements but its `__main__` guard's body, and the
definitions its importers use (`mod.name`, `from mod import name`) and those name, transitively.
So a config reader whose selftest imports a builder lends a lane that calls the reader none of the
builder's cargo calls. A module whose use is not read (the module passed as a value, `import *`,
`import_module`) or that can reach a definition by a name no code spells (`globals()`,
`sys.modules`, `eval`, a module `__getattr__`, running itself) is read whole.

## Comparing two trees

The declaration is metadata about the lanes, as a build file is about its targets, and a
comparison evaluates both trees under declarations it can name. `explain` and `select` read
the base with `decls_from=head`: a lane the base's `lanes.toml` declares is read with the
base's entry, and a lane it has no entry for (every lane, when the base has no `lanes.toml`) is
read with the head's. So a lane whose entry differs between the trees moves, since the entry is
in its spec, and a lane the base did not declare moves only when its inputs differ. A single
tree read without `decls_from` still refuses an undeclared lane: a tree's own digest is never
taken from another tree's declaration unless a comparison asks for it.

## Opaque lanes (RFC 0001 5.4)

A lane is opaque when its inputs cannot be read off its commands: a cargo call whose package set is
computed (`-p "$pkg"`) or depends on a directory the reader cannot see, a script that spawns a
cargo build itself, or a lane that runs another lane (`run-ci.sh --layer`); unless its entry
declares the `packages` or `legs` it builds. A `-p "$x"` whose `x` is the variable of a `for`
over literal words names those words, and so does one whose `x` the text binds only to literal
words (`x=wz-a`); a word of a script's argv list that is a name its module binds once to a
string (`PACKAGE = "wz-a"`) is that string. A cargo call that reads the package graph and
builds nothing (`cargo metadata`, `cargo tree`, `cargo vendor`, from the shell or from a
script's argv list) is not opaque: it
reads what `lane_graph.manifest_inputs` lists, the manifests and locks of the tree and what
decides the targets cargo discovers. An opaque lane's inputs are the WHOLE tree, so its digest is still
sound (an equal digest is an equal tree) and moves on every change: it is always selected. The record
names why (`"opaque": [reasons]`); RFC 0001 counts each as a debt of its entry.

## Soundness, and what holds it

A digest is sound when inputs(L, t) holds every tracked file L reads (RFC 0001 4.4). The derivation
above over-approximates where it can (the lock's resolve over every feature, a directory named
means all of it) but a file a lane reaches through a computed path is found only by running it:
`lane_input_closure.py` is that traced audit, and the sampled re-check and the hosted audit of
stages M5 and M6 are the other two. Until a lane has been audited its digest is as sound as its
declaration; the record carries the declaration so that an auditor sees which.
"""

from __future__ import annotations

import argparse
import ast
import bisect
import contextlib
import functools
import hashlib
import io
import json
import os
import posixpath
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Callable, Iterator, NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lane_decl  # noqa: E402
import lane_graph  # noqa: E402
import runci_plan  # noqa: E402
from git_tree import Fixture, GitError, GitTree, git  # noqa: E402

SCHEMA = "wz-lane-digest/2"
RUNCI = "scripts/run-ci.sh"
PLANNER = "scripts/lib/runci_plan.py"
WORKFLOWS = tuple(str(p) for p in runci_plan.HOSTED_WORKFLOWS)
TOOLCHAIN = "rust-toolchain.toml"
BX_TOML = "bx.toml"
ORACLE_PIN = "scripts/zenoh-c-oracle.pin"
UPSTREAM = "scripts/lib/upstream_feature_census.py"
#: What a machine reports about itself, given the pinned channel (None when the tree pins none).
EnvReader = Callable[[str | None], dict[str, str]]


class DigestError(RuntimeError):
    """The tree's digest for the lane cannot be computed; the message says what is missing."""


# -- canonical bytes -----------------------------------------------------------------------------


def _canon(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_of(rec: dict) -> str:
    """D(L, t) of a record: SHA-256 over the schema word and the three documents, each preceded by
    its length, so no two different records share a byte string."""
    h = hashlib.sha256()
    for part in (rec["schema"].encode("utf-8"), _canon(rec["spec"]), _canon(rec["env"]), _canon(rec["inputs"])):
        h.update(str(len(part)).encode("ascii") + b":")
        h.update(part)
    return h.hexdigest()


def _sha(text: str | bytes) -> str:
    return hashlib.sha256(text.encode("utf-8") if isinstance(text, str) else text).hexdigest()


# -- the dispatch script ---------------------------------------------------------------------------

_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
#: A function definition at the start of a command: `name() {`, `function name {`, `function name() {`.
_HEADER = re.compile(r"function[ \t]+([A-Za-z_][\w:.-]*)(?:[ \t]*\([ \t]*\))?|([A-Za-z_][\w:.-]*)[ \t]*\([ \t]*\)")
#: A word that assigns (`x=`, `x+=`, `x[i]=`); one that ends at the `=` and meets a `(` starts an array.
_ASSIGNMENT = re.compile(r"[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=")
#: The reserved word each closing word closes.
_CLOSES = {"fi": "if", "done": "do", "esac": "case"}
#: Reserved words after which a command starts.
_LEADS = frozenset({"then", "else", "elif", "while", "until", "!", "time"})


class ShellParseError(ValueError):
    """A shell text the reader cannot split into its definitions; the message says where."""


class ShellDefs(NamedTuple):
    """A shell text as `parse_shell` splits it (see "The dispatch script")."""

    #: each top-level function's definition, from its name to its closing brace, without comments
    funcs: dict[str, str]
    #: the code outside those functions, without comments and without the dispatch lines
    top: str


class _ShellReader:
    """Bash's tokenizing, as far as finding where each top-level function starts and ends needs:
    quotes, expansions, heredoc bodies and comments are skipped whole, and `{ }`, `if fi`,
    `case esac` and `do done` count only where they are reserved words, at the start of a command.
    What it cannot place raises ShellParseError; it never guesses a boundary."""

    def __init__(self, text: str) -> None:
        self.t = text
        self.n = len(text)
        #: (start, end) of every comment, the newline that ends it excluded
        self.comments: list[tuple[int, int]] = []
        #: (name, start, the index after its closing brace) of each top-level function
        self.defs: list[tuple[str, int, int]] = []

    def fail(self, at: int, what: str) -> ShellParseError:
        return ShellParseError(f"line {self.t.count(chr(10), 0, at) + 1}: {what}")

    def comment(self, i: int) -> int:
        j = self.t.find("\n", i)
        end = self.n if j < 0 else j
        self.comments.append((i, end))
        return end

    def squote(self, i: int) -> int:
        j = self.t.find("'", i + 1)
        if j < 0:
            raise self.fail(i, "a ' is not closed")
        return j + 1

    def escaped(self, i: int, close: str, what: str) -> int:
        """The index after the `close` that ends the span opened at i, a backslash escaping."""
        start = i
        i += 1
        while i < self.n:
            c = self.t[i]
            if c == "\\":
                i += 2
            elif c == close:
                return i + 1
            else:
                i += 1
        raise self.fail(start, f"{what} is not closed")

    def dquote(self, i: int) -> int:
        t, start = self.t, i
        i += 1
        while i < self.n:
            c = t[i]
            if c == "\\":
                i += 2
            elif c == '"':
                return i + 1
            elif c == "$":
                i = self.dollar(i)
            elif c == "`":
                i = self.escaped(i, "`", "a backtick")
            else:
                i += 1
        raise self.fail(start, 'a " is not closed')

    def dollar(self, i: int) -> int:
        """The index after the expansion the `$` at i starts (i + 1 for a plain `$`)."""
        t = self.t
        if t.startswith("$((", i):
            return self.matched(i + 3, 2, "a $((")
        if t.startswith("$(", i):
            return self.run(i + 2, nested=True)
        if t.startswith("${", i):
            return self.matched(i + 2, 1, "a ${", "{", "}")
        if t.startswith("$'", i):
            return self.escaped(i + 1, "'", "a $' string")
        if t.startswith('$"', i):
            return self.dquote(i + 1)
        return i + 1

    def matched(self, i: int, depth: int, what: str, opening: str = "(", closing: str = ")",
                comments: bool = False) -> int:
        """The index after the `closing` that brings `depth` to zero; quotes and expansions are
        skipped whole, and with `comments` a `#` after a blank starts one (an array's)."""
        t, start = self.t, i
        while i < self.n:
            c = t[i]
            if c == "\\":
                i += 2
            elif c == "'":
                i = self.squote(i)
            elif c == '"':
                i = self.dquote(i)
            elif c == "`":
                i = self.escaped(i, "`", "a backtick")
            elif c == "$":
                i = self.dollar(i)
            elif comments and c == "#" and t[i - 1] in " \t\n(":
                i = self.comment(i)
            elif c == opening:
                depth += 1
                i += 1
            elif c == closing:
                depth -= 1
                i += 1
                if depth == 0:
                    return i
            else:
                i += 1
        raise self.fail(start, f"{what} is not closed")

    def word_end(self, i: int) -> int:
        """The index after the word at i: up to a blank or an operator outside quotes."""
        t, start = self.t, i
        while i < self.n:
            c = t[i]
            if c in " \t\r\n;&|<>)":
                break
            if c == "(":
                if i > start and t[i - 1] in "@!+*?":
                    i = self.matched(i + 1, 1, "a pattern group")
                    continue
                break
            if c == "\\":
                i += 2
            elif c == "'":
                i = self.squote(i)
            elif c == '"':
                i = self.dquote(i)
            elif c == "`":
                i = self.escaped(i, "`", "a backtick")
            elif c == "$":
                i = self.dollar(i)
            else:
                i += 1
        return i

    def bodies(self, i: int, pending: list[tuple[str, bool]]) -> int:
        """The index after the heredoc bodies that start at i, one per pending delimiter."""
        t = self.t
        for delim, strip in pending:
            while True:
                if i >= self.n:
                    raise self.fail(self.n, f"the heredoc ending in {delim} has no end")
                j = t.find("\n", i)
                line = t[i:] if j < 0 else t[i:j]
                i = self.n if j < 0 else j + 1
                if (line.lstrip("\t") if strip else line) == delim:
                    break
        return i

    def word(self, i: int, command: bool, stack: list[tuple[str, str | None, int]],
             nested: bool) -> tuple[int, bool]:
        """Read the word at i: (the index after it, whether a command starts after it)."""
        t = self.t
        if command:
            m = _HEADER.match(t, i)
            if m:
                name = m.group(1) or m.group(2)
                j = m.end()
                while j < self.n and t[j] in " \t\r\n":
                    j += 1
                if t.startswith("{", j) and (j + 1 >= self.n or t[j + 1] in " \t\r\n"):
                    stack.append(("{", name, i))
                    return j + 1, True
                raise self.fail(i, f"the body of function {name} is not a {{ }} group")
        start = i
        i = self.word_end(i)
        if i == start:
            raise self.fail(i, f"no word at {t[i:i + 10]!r}")
        w = t[start:i]
        if command:
            if w == "{":
                stack.append(("{", None, start))
                return i, True
            if w == "}":
                if not stack or stack[-1][0] != "{":
                    raise self.fail(start, "a } closes no {")
                _, name, first = stack.pop()
                if name is not None and not stack and not nested:
                    self.defs.append((name, first, i))
                return i, False
            if w in ("if", "do", "case"):
                stack.append((w, None, start))
                return i, w != "case"
            if w in _CLOSES:
                if not stack or stack[-1][0] != _CLOSES[w]:
                    raise self.fail(start, f"{w} closes no {_CLOSES[w]}")
                stack.pop()
                return i, False
            if w in _LEADS:
                return i, True
            if _ASSIGNMENT.match(w):
                if w.endswith("=") and t.startswith("(", i):
                    i = self.matched(i + 1, 1, "an array", comments=True)
                return i, True
        elif _ASSIGNMENT.fullmatch(w) and t.startswith("(", i):
            return self.matched(i + 1, 1, "an array", comments=True), False
        return i, False

    def run(self, i: int, nested: bool) -> int:
        """Read commands from i. Nested (the body of a `$(` or `<(`), return the index after the
        `)` that closes it; else read to the end, recording the top-level functions."""
        t, n = self.t, self.n
        stack: list[tuple[str, str | None, int]] = []
        command = True
        pending: list[tuple[str, bool]] = []
        while i < n:
            c = t[i]
            if c == "\n":
                i += 1
                if pending:
                    i = self.bodies(i, pending)
                    pending = []
                command = True
            elif c in " \t\r":
                i += 1
            elif c == "\\" and t.startswith("\n", i + 1):
                i += 2
            elif c == "#":
                i = self.comment(i)
            elif c == "&" and t.startswith(">", i + 1):
                i += 2
                while i < n and t[i] == ">":
                    i += 1
            elif c in ";&|":
                i += 1
                command = True
            elif c in "<>":
                if t.startswith("<<<", i):
                    i += 3
                elif t.startswith("<<", i):
                    i += 2
                    strip = t.startswith("-", i)
                    if strip:
                        i += 1
                    while i < n and t[i] in " \t":
                        i += 1
                    j = self.word_end(i)
                    if j == i:
                        raise self.fail(i, "a heredoc names no delimiter")
                    pending.append((re.sub(r"[\"'\\]", "", t[i:j]), strip))
                    i = j
                elif t.startswith("(", i + 1):
                    i = self.run(i + 2, nested=True)
                    command = False
                else:
                    i += 1
                    while i < n and t[i] in "<>&|-":
                        i += 1
            elif c == "(":
                if command and t.startswith("(", i + 1):
                    i = self.matched(i + 2, 2, "a ((")
                    command = False
                else:
                    stack.append(("(", None, i))
                    i += 1
                    command = True
            elif c == ")":
                top = stack[-1][0] if stack else None
                if top == "(":
                    stack.pop()
                elif top != "case":
                    if nested and top is None:
                        return i + 1
                    raise self.fail(i, "a ) closes nothing")
                i += 1
                command = True
            else:
                i, command = self.word(i, command, stack, nested)
        if nested:
            raise self.fail(n, "a $( or <( is not closed")
        if pending:
            raise self.fail(n, "a heredoc at the end has no body")
        if stack:
            raise self.fail(stack[-1][2], f"a {stack[-1][0]} is not closed")
        return i


def parse_shell(text: str) -> ShellDefs:
    """Split a shell text into its top-level functions and the code outside them (see "The dispatch
    script"). A redefinition keeps both texts under the name. Raises ShellParseError."""
    reader = _ShellReader(text)
    reader.run(0, nested=False)
    # A comment that is its whole line goes with its line; one after code, with the blanks before it.
    comments: list[tuple[int, int]] = []
    for a, b in sorted(reader.comments):
        line = text.rfind("\n", 0, a) + 1
        if not text[line:a].strip(" \t"):
            comments.append((line, min(b + 1, len(text))))
        else:
            while text[a - 1] in " \t":
                a -= 1
            comments.append((a, b))
    starts = [a for a, _ in comments]

    def code(lo: int, hi: int) -> str:
        out: list[str] = []
        at = lo
        k = bisect.bisect_left(starts, lo)
        while k < len(comments) and comments[k][0] < hi:
            a, b = comments[k]
            out.append(text[at:a])
            at = min(b, hi)
            k += 1
        out.append(text[at:hi])
        return "".join(out)

    funcs: dict[str, str] = {}
    top: list[str] = []
    at = 0
    for name, start, close in reader.defs:
        nl = text.find("\n", close)
        eol = len(text) if nl < 0 else nl
        top.append(code(at, start))
        funcs[name] = funcs.get(name, "") + code(start, close)
        # The rest of the closing line goes with the function when it holds nothing to run.
        at = (len(text) if nl < 0 else nl + 1) if not code(close, eol).strip() else close
    top.append(code(at, len(text)))
    return ShellDefs(funcs, runci_plan.DISPATCH.sub("", "".join(top)))


def executed(text: str) -> str:
    """The lines of a shell or python text that are not whole-line comments: a path or a call named
    only in a comment runs nothing. A continuation is joined first, as the shell joins it."""
    joined = text.replace("\\\n", "  ")
    return "\n".join(line for line in joined.splitlines() if not line.lstrip().startswith("#"))


def function_closure(funcs: dict[str, str], seeds: set[str]) -> list[str]:
    """Every function the seeds name, and every function those name, transitively."""
    out: set[str] = set()
    stack = [s for s in seeds if s in funcs]
    while stack:
        name = stack.pop()
        if name in out:
            continue
        out.add(name)
        stack.extend(w for w in set(_WORD.findall(executed(funcs[name]))) if w in funcs and w not in out)
    return sorted(out)


# -- what a text names ---------------------------------------------------------------------------

_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+")
_SIBLING = re.compile(r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+\.(?:sh|bash|py|tcl|json|toml|tsv|txt|yaml|yml|cfg|conf|pin))\b")
_SCRIPT_SUFFIX = (".sh", ".bash", ".py", ".tcl")
_ROOT_VARS = re.compile(r"^(?:\$\{?(?:ROOT|REPO|repo|root|PWD|REPO_ROOT|repo_root)\}?/|\./)+")


class Named(NamedTuple):
    """What a text names: scripts it runs or imports, data files it reads, directories, gitlinks,
    and the modules a python text imports with the names of each it uses (None: every one)."""

    scripts: set[str]
    files: set[str]
    dirs: set[str]
    links: set[str]
    imported: dict[str, frozenset[str] | None]


# A python line that starts a program: what it names with a script's suffix is run, not read.
_PY_SPAWN = re.compile(r"subprocess|sys\.executable|os\.exec|[\"'](?:bash|sh|python3?)[\"']")


def _div_segments(node: ast.AST, consumed: set[int]) -> list[str]:
    """The string segments a `a / "b" / "c"` chain ends in (["b", "c"]); the inner links of the
    chain are marked consumed, so a walk does not read `a / "b"` again as the directory "b"."""
    segs: list[str] = []
    while (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
           and isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)):
        consumed.add(id(node))
        segs.insert(0, node.right.value)
        node = node.left
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        segs.insert(0, node.value)
    return segs


class PyRefs(NamedTuple):
    #: the top-level modules it imports
    imports: list[str]
    #: (a path-like string of its code, whether the line it is on starts a program)
    found: list[tuple[str, bool]]
    #: each argv list that starts with "cargo": (its subcommand, "?" when that is no constant;
    #: every word after "cargo" when each is a constant, else None)
    cargo: list[tuple[str, tuple[str, ...] | None]]
    #: an argv list naming run-ci.sh and --layer
    runs_lane: bool
    #: for each module in `imports`, the top-level names of it the code uses (`mod.name`,
    #: `from mod import name`), or None when a use cannot be read: the module bound and used as a
    #: value, `from mod import *`, a dotted import, `import_module`
    uses: dict[str, frozenset[str] | None]


#: Cargo subcommands that read the package graph and build nothing: their inputs are
#: `lane_graph.manifest_inputs`, not the closure of a package. `vendor` copies the sources the
#: lock names out of the registry and compiles none of the tree's.
CARGO_READS = frozenset({"metadata", "tree", "locate-project", "pkgid", "verify-project", "read-manifest",
                         "vendor"})
#: Cargo words that ask cargo about itself and read nothing of the tree (env holds `cargo -V`).
CARGO_ASKS = frozenset({"-V", "--version", "version", "-vV", "--list"})


def _word(e: ast.expr, consts: dict[str, str]) -> str | None:
    """The word an argv element spells: a string literal, or a name the module binds once to one
    (`_module_constants`); None for anything computed."""
    if isinstance(e, ast.Constant) and isinstance(e.value, str):
        return e.value
    if isinstance(e, ast.Name) and e.id in consts:
        return consts[e.id]
    return None


def _cargo_argv(elts: list[ast.expr],
                consts: dict[str, str] | None = None) -> tuple[str, tuple[str, ...] | None] | None:
    """(the subcommand, the words after "cargo" when all are constants) of an argv list whose
    first string literal is "cargo", or None for any other list. A word after it is a constant
    when it is a string literal or a name of `consts`. The subcommand is "?" when the word that
    holds it is not a constant; a toolchain word (`"+stable"`, `f"+{channel}"`) before it is
    skipped, as cargo skips it."""
    first = next((i for i, e in enumerate(elts) if isinstance(e, ast.Constant) and isinstance(e.value, str)), None)
    if first is None or elts[first].value != "cargo":
        return None
    rest = [_word(e, consts or {}) for e in elts[first + 1:]]
    words = tuple(w for w in rest if w is not None)
    constant = first == 0 and len(words) == len(rest)
    sub = "?"
    for e, w in zip(elts[first + 1:], rest):
        if w is not None:
            if w.startswith("+"):
                continue
            sub = w
        elif (isinstance(e, ast.JoinedStr) and e.values and isinstance(e.values[0], ast.Constant)
                and str(e.values[0].value).startswith("+")):
            continue
        break
    return sub, (words if constant else None)


#: Calls that reach a top-level definition by a name no code spells.
_DYNAMIC_CALLS = frozenset({"globals", "vars", "eval", "exec", "__import__"})


def _dynamic(node: ast.AST) -> bool:
    """Whether a node can reach a module's definitions by a computed name: a call of
    `_DYNAMIC_CALLS`, `sys.modules` or a `__dict__`."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in _DYNAMIC_CALLS
    if isinstance(node, ast.Attribute):
        return node.attr == "__dict__" or (node.attr == "modules" and isinstance(node.value, ast.Name)
                                           and node.value.id == "sys")
    return False


def _bound_names(node: ast.AST) -> list[str]:
    """The names a node binds: an assignment's, a parameter's, an import's, a definition's, a
    `global`'s, an `except ... as`'s, a pattern's."""
    if isinstance(node, ast.Name):
        return [] if isinstance(node.ctx, ast.Load) else [node.id]
    if isinstance(node, ast.arg):
        return [node.arg]
    if isinstance(node, ast.alias):
        return [(node.asname or node.name).split(".")[0]]
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return list(node.names)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.ExceptHandler):
        return [node.name] if node.name else []
    name = getattr(node, "name", None) if type(node).__name__ in ("MatchAs", "MatchStar") else None
    rest = getattr(node, "rest", None) if type(node).__name__ == "MatchMapping" else None
    return [n for n in (name, rest) if isinstance(n, str)]


def _module_constants(module: ast.Module) -> dict[str, str]:
    """The names a module binds exactly once, by a top-level assignment of a string literal
    (`PACKAGE = "wz-x"`), with their strings; an argv list that names one spells that word. A
    module that reaches a definition by a computed name (`_dynamic`) has none."""
    once: dict[str, str] = {}
    for stmt in module.body:
        target = (stmt.targets[0] if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                  else stmt.target if isinstance(stmt, ast.AnnAssign) else None)
        value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
        if isinstance(target, ast.Name) and isinstance(value, ast.Constant) and isinstance(value.value, str):
            once[target.id] = value.value
    bindings: dict[str, int] = {}
    for node in ast.walk(module):
        if _dynamic(node):
            return {}
        for name in _bound_names(node):
            bindings[name] = bindings.get(name, 0) + 1
    return {name: value for name, value in once.items() if bindings.get(name) == 1}


def _is_main_guard(stmt: ast.stmt) -> bool:
    """`if __name__ == "__main__":`, whose body an import does not run."""
    test = stmt.test if isinstance(stmt, ast.If) else None
    return (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == "__name__"
            and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq) and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value == "__main__")


def _lib_reached(module: ast.Module, used: frozenset[str], lines: list[str]) -> list[ast.AST] | None:
    """The nodes importing the module runs when its importers use its top-level names `used`,
    parents before their children: its top-level statements but the body of its `__main__`
    guard, what loading it evaluates of its definitions (decorators, defaults, base classes, a
    class's own statements), the body of every decorated function (the decorator may keep it),
    and the body of every top-level definition `used` or a reached node names, transitively.
    None, the whole text, when the module defines `__getattr__`, or a reached node reaches a
    definition by a computed name (`_dynamic`) or starts the module as a program (`__file__`
    on a line that starts one)."""
    defs: dict[str, list[ast.stmt]] = {}
    for stmt in module.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defs.setdefault(stmt.name, []).append(stmt)
    if "__getattr__" in defs:
        return None
    roots: list[ast.AST] = []
    named: set[str] = set()

    def enter(name: str) -> None:
        if name not in defs or name in named:
            return
        named.add(name)
        for d in defs[name]:
            if isinstance(d, ast.ClassDef):
                roots.extend(s for s in d.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)))
            else:
                roots.extend(d.body)

    for stmt in module.body:
        if isinstance(stmt, ast.ClassDef):
            roots.extend([*stmt.decorator_list, *stmt.bases, *(k.value for k in stmt.keywords)])
            roots.extend(s for s in stmt.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)))
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            roots.extend([*stmt.decorator_list, *stmt.args.defaults, *(d for d in stmt.args.kw_defaults if d)])
            if stmt.decorator_list:
                enter(stmt.name)
        elif _is_main_guard(stmt):
            roots.append(stmt.test)
            roots.extend(stmt.orelse)
        else:
            roots.append(stmt)
    for name in sorted(used):
        enter(name)
    out: list[ast.AST] = []
    while roots:
        node = roots.pop()
        out.append(node)
        if _dynamic(node):
            return None
        if isinstance(node, ast.Name):
            n = getattr(node, "lineno", 0)
            if node.id == "__file__" and 0 < n <= len(lines) and _PY_SPAWN.search(lines[n - 1]):
                return None
            enter(node.id)
        roots.extend(ast.iter_child_nodes(node))
    return out


@functools.lru_cache(maxsize=None)
def python_refs(text: str, given: frozenset[str] | None = None,
                used: frozenset[str] | None = None) -> PyRefs | None:
    """What a python text names, read by its syntax: a docstring, a bare string statement and a
    comment are no reference. None when the text does not parse. With `given`, the dests of the
    `store_true` options its call sites pass (`call_modes`), only the code a run with those
    options reaches (`_py_reached`), or the whole text when that cannot be read off it. With
    `used`, the text is a module imported and not run, and its importers use these of its
    top-level names: only the code importing it reaches (`_lib_reached`), or the whole text when
    that cannot be read off it (`given` is then not read)."""
    try:
        module = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    lines = text.splitlines()
    reached = None
    if used is not None:
        reached = _lib_reached(module, used, lines)
    elif given is not None:
        opts = py_options(text)
        reached = _py_reached(module, opts, given) if opts is not None else None
    consts = _module_constants(module)
    bare: set[int] = set()
    consumed: set[int] = set()
    imports: list[str] = []
    found: list[tuple[str, bool]] = []
    cargo: list[tuple[str, tuple[str, ...] | None]] = []
    runs_lane = False
    # The names an import binds to a module, and what of each module the code uses.
    bound: dict[str, set[str]] = {}
    uses: dict[str, set[str] | None] = {}
    for node in ast.walk(module):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            bare.add(id(node.value))

    def runs(node: ast.AST) -> bool:
        n = getattr(node, "lineno", 0)
        return 0 < n <= len(lines) and bool(_PY_SPAWN.search(lines[n - 1]))

    def use(mod: str, names: set[str] | None) -> None:
        before = uses.setdefault(mod, set())
        if names is None or before is None:
            uses[mod] = None
        else:
            before.update(names)

    nodes = list(ast.walk(module)) if reached is None else reached
    for node in nodes:
        if isinstance(node, (ast.List, ast.Tuple)):
            words = [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            argv = _cargo_argv(node.elts, consts)
            if argv is not None:
                cargo.append(argv)
            # Recognises a lane call in a module's source and never makes one, so the decline
            # assertion (`WZ_DECLINED_EXPECT`) is not this reader's to arm or to drop.
            runs_lane = runs_lane or (any(w.endswith("run-ci.sh") for w in words) and "--layer" in words)
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name.split(".")[0]
                imports.append(mod)
                if "." in alias.name:
                    use(mod, None)
                else:
                    bound.setdefault(alias.asname or mod, set()).add(mod)
                    use(mod, set())
        elif isinstance(node, ast.ImportFrom):
            if node.module and not node.level:
                mod = node.module.split(".")[0]
                imports.append(mod)
                star = "." in node.module or any(alias.name == "*" for alias in node.names)
                use(mod, None if star else {alias.name for alias in node.names})
        elif isinstance(node, ast.Call):
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            first = node.args[0] if node.args else None
            if name == "import_module" and isinstance(first, ast.Constant) and isinstance(first.value, str):
                imports.append(first.value.split(".")[0])
                use(first.value.split(".")[0], None)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and id(node) not in consumed:
            segs = _div_segments(node, consumed)
            if segs:
                found.append(("/".join(segs), runs(node)))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in bare:
            for tok in _PATH.findall(node.value):
                found.append((tok, runs(node)))
            for name in _SIBLING.findall(node.value):
                found.append((name, runs(node)))
    # A module's name read as `mod.name` uses that name; read any other way (passed, compared,
    # rebound) it is a value whose use is not read.
    attr_bases = {id(n.value) for n in nodes if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
    for node in nodes:
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in bound:
            for mod in bound[node.value.id]:
                use(mod, {node.attr})
        elif isinstance(node, ast.Name) and node.id in bound and id(node) not in attr_bases:
            for mod in bound[node.id]:
                use(mod, None)
    return PyRefs(imports, found, cargo, runs_lane,
                  {mod: (None if names is None else frozenset(names)) for mod, names in uses.items()})


# -- a python script's modes -----------------------------------------------------------------------

#: argparse actions whose option takes no value on the command line.
_NO_VALUE = frozenset({"store_true", "store_false", "store_const", "append_const", "count", "help", "version"})
#: What sets an option, or calls a function, by a way no call site and no name shows.
_UNREAD_MODES = ("sys.argv", "set_defaults", "fromfile_prefix_chars", "Namespace(", "__dict__", "setattr(",
                 "vars(", "globals()", "sys.modules", "eval(", "exec(")


class PyOptions(NamedTuple):
    """A script's argparse options, as a call site spells them (`py_options`)."""

    #: each option string of a `store_true` option -> its dest
    flags: dict[str, str]
    #: the option strings that take exactly one value
    valued: frozenset[str]


def _dest(names: list[str], kw: dict[str, ast.expr]) -> str:
    dest = kw.get("dest")
    if isinstance(dest, ast.Constant) and isinstance(dest.value, str):
        return dest.value
    longs = [n for n in names if n.startswith("--")]
    return (longs or names)[0].lstrip("-").replace("-", "_")


@functools.lru_cache(maxsize=None)
def py_options(text: str) -> PyOptions | None:
    """The options of a script that parses its own command line once, with argparse; None when it
    has no `store_true` option a call site alone decides, or when something else could set one or
    call a function by a name no code spells (`_UNREAD_MODES`, an argument list given to
    `parse_args`, an action of its own)."""
    if any(word in text for word in _UNREAD_MODES):
        return None
    try:
        module = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    flags: dict[str, str] = {}
    valued: set[str] = set()
    others: set[str] = set()
    for node in ast.walk(module):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr in ("parse_args", "parse_known_args") and (node.args or node.keywords):
            return None
        if node.func.attr != "add_argument":
            continue
        names = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        if not names:
            continue
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        action = kw.get("action")
        if action is not None and not (isinstance(action, ast.Constant) and isinstance(action.value, str)):
            return None
        word = "store" if action is None else action.value
        default = kw.get("default")
        if (word == "store_true" and all(n.startswith("-") for n in names)
                and (default is None or (isinstance(default, ast.Constant) and default.value is False))):
            flags.update((n, _dest(names, kw)) for n in names)
            continue
        # Any other option sharing a dest with a flag can set it without the flag.
        others.add(_dest(names, kw))
        nargs = kw.get("nargs")
        if word not in _NO_VALUE and (nargs is None or (isinstance(nargs, ast.Constant) and nargs.value == 1)):
            valued.update(n for n in names if n.startswith("-"))
    flags = {o: d for o, d in flags.items() if d not in others}
    return PyOptions(flags, frozenset(valued)) if flags else None


def _py_reached(module: ast.Module, opts: PyOptions, given: frozenset[str]) -> list[ast.AST] | None:
    """The nodes a run of the script reaches when its command line holds the `store_true` options
    whose dests are `given` and no other, parents before their children: its module-level
    statements, what loading it evaluates of its definitions (decorators, defaults, base classes),
    and the body of every top-level function or class a reached node names; never the body of an
    `if <args>.<dest>:` whose dest is not given (`<args>` a name `parse_args` binds, the dest no
    code assigns). A string equal to an option, outside `add_argument` (the script running itself
    with that flag), gives its dest too. None when no such body is left out."""
    dests = set(opts.flags.values())
    parsed: set[str] = set()
    declared: set[int] = set()
    for node in ast.walk(module):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr in ("parse_args", "parse_known_args")):
            for target in node.targets:
                first = target.elts[0] if isinstance(target, ast.Tuple) and target.elts else target
                if isinstance(first, ast.Name):
                    parsed.add(first.id)
        elif isinstance(node, ast.Attribute) and not isinstance(node.ctx, ast.Load):
            dests.discard(node.attr)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument":
            declared.update(id(a) for a in node.args)
    defs = {s.name: s for s in module.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    on = set(given)
    while True:
        roots: list[ast.AST] = []
        for stmt in module.body:
            if isinstance(stmt, ast.ClassDef):
                roots.extend([*stmt.decorator_list, *stmt.bases, *(k.value for k in stmt.keywords)])
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                roots.extend([*stmt.decorator_list, *stmt.args.defaults, *(d for d in stmt.args.kw_defaults if d)])
            else:
                roots.append(stmt)
        out: list[ast.AST] = []
        named: set[str] = set()
        more: set[str] = set()
        left_out = False
        while roots:
            node = roots.pop()
            out.append(node)
            test = node.test if isinstance(node, ast.If) else None
            if (isinstance(test, ast.Attribute) and isinstance(test.value, ast.Name) and test.value.id in parsed
                    and test.attr in dests and test.attr not in on):
                roots.append(test)
                roots.extend(node.orelse)
                left_out = True
                continue
            if isinstance(node, ast.Name) and node.id in defs and node.id not in named:
                named.add(node.id)
                roots.extend(defs[node.id].body)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in declared:
                more.update(d for o, d in opts.flags.items() if o == node.value)
            roots.extend(ast.iter_child_nodes(node))
        if more <= on:
            return out if left_out else None
        on |= more


#: The program a python script is run by, as a word of a command line.
_INTERPRETER = re.compile(r"(?:.*/)?python(?:3(?:\.\d+)?)?")
#: What may stand before a script run as a command of its own: a line's start or an operator.
_COMMAND_START = re.compile(r"(?:^|[;&|(]|\bexec|\bthen|\bdo|\belse)\s*$")


def _site_words(rest: str) -> list[str]:
    """The words of a command line after a script's name, up to the first operator outside quotes."""
    words: list[str] = []
    word = ""
    quote = ""
    i = 0
    while i < len(rest):
        c = rest[i]
        if quote:
            word += c
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
            word += c
        elif c in " \t":
            if word:
                words.append(word)
            word = ""
        elif c in ";|&)<>`":
            break
        elif c == "\\":
            word += rest[i : i + 2]
            i += 1
        else:
            word += c
        i += 1
    if word and not quote:
        words.append(word)
    return words


def call_modes(text: str, path: str, opts: PyOptions | None) -> frozenset[str] | None:
    """The dests of the `store_true` options of the python script `path` that the lines of a shell
    text running it pass. None, every mode, when the script's options cannot be read (`opts` None),
    when no line runs it, or when a line may pass more than its words show: a word the shell computes
    where an option could stand, a cluster of short options, the script named anywhere but after its
    interpreter or at the start of a command (an assignment, a loop's list)."""
    if opts is None:
        return None
    site = re.compile(rf"(?<![\w.-]){re.escape(posixpath.basename(path))}(?![\w.-])")
    given: set[str] = set()
    found = False
    for line in executed(text).splitlines():
        for m in site.finditer(line):
            # Back over the rest of the word the name ends (`"$ROOT/scripts/lib/x.py"`).
            k = m.start()
            while k > 0 and (line[k - 1].isalnum() or line[k - 1] in "_./${}-\"'"):
                k -= 1
            before = [w for w in re.split(r"[\s\"'=(`]+", line[:k]) if w]
            while before and before[-1].startswith("-"):
                before.pop()
            if not (before and _INTERPRETER.fullmatch(before[-1])) and not _COMMAND_START.search(line[:k]):
                return None
            found = True
            # The words after the one the name ends (its closing quote, if any, is part of it).
            words = _site_words(re.sub(r"^[^\s;|&)<>]*", "", line[m.end():]))
            i = 0
            while i < len(words):
                raw = words[i]
                i += 1
                if "$" in raw or "`" in raw:
                    return None
                w = raw.replace('"', "").replace("'", "")
                if w == "--":
                    break
                if not w.startswith("-") or w == "-":
                    continue
                opt, eq, _ = w.partition("=")
                if opt.startswith("--"):
                    # argparse takes a unique prefix of a long option; every option it could be counts.
                    hit = {d for o, d in opts.flags.items() if o.startswith(opt)}
                    takes = any(v.startswith(opt) for v in opts.valued)
                else:
                    hit = {d for o, d in opts.flags.items() if o == opt}
                    takes = opt in opts.valued
                    if not hit and not takes and len(opt) > 2:
                        return None
                given |= hit
                if takes and not hit and not eq:
                    i += 1
    return frozenset(given) if found else None


def names_in(text: str, base: str, tree, dirs: set[str], kind: str,
             given: frozenset[str] | None = None, used: frozenset[str] | None = None) -> Named:
    """What a text names, relative to the root or to `base`, the directory of its file.

    `kind` "shell": every script it names runs (`bash x.sh`, `source x.sh`, `python3 x.py`) and every
    other file it names is read. "python": what it imports is `imported`, with the names of it the
    code uses, and a script named on a line that starts a program runs; every other path in a
    string of its code is read (one in a docstring or a comment is not). "code": what it imports
    runs, and nothing it reads -- the planner, whose part in a unit is already the unit and the
    hosted env the spec holds. `given` narrows a "python" text to the code its call sites' options
    reach, `used` to the code importing it reaches (`python_refs`)."""
    scripts: set[str] = set()
    files: set[str] = set()
    found_dirs: set[str] = set()
    links: set[str] = set()
    imported: dict[str, frozenset[str] | None] = {}
    gitlinks = tree.gitlinks()

    def places(candidate: str) -> set[str]:
        # A path written under a variable (`$ROOT/scripts/x.sh`) is read as the token
        # `ROOT/scripts/x.sh`: every tail of two or more segments is tried too.
        parts = candidate.split("/")
        tails = {"/".join(parts[i:]) for i in range(max(1, len(parts) - 1))} | {candidate}
        options = {posixpath.normpath(t) for t in tails} | {posixpath.normpath(posixpath.join(base, candidate))}
        return {p for p in options if not (p.startswith("../") or p in (".", ".."))}

    def take(candidate: str, runs: bool) -> None:
        for path in places(candidate):
            if path in gitlinks:
                links.add(path)
            elif path in tree.entries:
                (scripts if runs and path.endswith(_SCRIPT_SUFFIX) else files).add(path)
            elif path in dirs:
                found_dirs.add(path)

    if kind == "shell":
        body = executed(text)
        for tok in _PATH.findall(body):
            take(_ROOT_VARS.sub("", tok), True)
        for name in _SIBLING.findall(body):
            take(name, True)
        return Named(scripts, files, found_dirs, links, imported)
    refs = python_refs(text, given if kind == "python" else None, used if kind == "python" else None)
    if refs is None:
        # Not python this reader can parse: read it as a shell text reads, which runs more.
        return names_in(text, base, tree, dirs, "shell")
    for mod in refs.imports:
        candidate = posixpath.join(base, mod + ".py")
        if kind != "python":
            take(candidate, True)
            continue
        names = refs.uses.get(mod)
        for path in places(candidate):
            if path in tree.entries and path not in gitlinks:
                before = imported.get(path, frozenset())
                imported[path] = None if names is None or before is None else before | names
    if kind == "python":
        for candidate, runs in refs.found:
            take(candidate, runs)
    if kind == "code":
        files.clear()
        found_dirs.clear()
        links.clear()
    return Named(scripts, files, found_dirs, links, imported)


# -- cargo calls ---------------------------------------------------------------------------------

_CARGO = re.compile(r"(?<![\w/.-])cargo(?:\s+\+[\w.-]+)?\s+([A-Za-z][\w-]*)([^\n;&|)]*)")
# A program's argv written as a list (`["cargo", "tree", ...]`), the shape a script spawns cargo in.
_SPAWNS_CARGO = re.compile(r"[\"']cargo[\"']\s*,")
_CD = re.compile(r"\bcd\s+[\"']?([^\s\"';&|)]+)")


class Call(NamedTuple):
    """One cargo call as read: the packages named, a manifest path, whether the whole workspace is
    asked, the directory a `cd` before it moved to, and why it cannot be read (empty when it can)."""

    sub: str
    packages: tuple[str, ...]
    manifest: str | None
    whole: bool
    cwd: str | None
    unresolved: str


_ASSIGN = re.compile(r"^\s*(?:local\s+|export\s+|readonly\s+)?([A-Za-z_]\w*)=([\"']?)([^\"'\s;()`]*)\2\s*$")
_VAR = re.compile(r"\$\{?([A-Za-z_]\w*)\}?")


def _expand(value: str, assigned: dict[str, str]) -> str:
    """`value` with the text's own plain assignments substituted (three rounds, for a variable
    defined through another); a variable the text does not assign is left as it is."""
    for _ in range(3):
        value = _VAR.sub(lambda m: assigned.get(m.group(1), m.group(0)), value)
    return value


#: A word of a python argv list that reads as one shell word.
_PLAIN_WORD = re.compile(r"[^\s\"'`$;&|()<>\\]+")
_FOR = re.compile(r"^\s*for\s+([A-Za-z_]\w*)\s+in\s+(.*?)\s*(?:;\s*do\b.*)?$")
_LITERAL_WORD = re.compile(r"([\"']?)([A-Za-z0-9_.+-]+)\1")
_REBINDS = re.compile(r"\b(?:read|local|declare|typeset|mapfile|readarray)\b")


def _constant_words(body: str) -> dict[str, list[str]]:
    """Each variable an executed shell text binds only by whole-line assignments of one literal
    word (`BIN=wz-x`, `local crate="wz-y"`), with every word it is given there. A variable the
    text binds any other way anywhere (`read`, `for`, `local` with no value, `+=`, `${X:=a}`, an
    assignment of a computed value) or names other than as `$X` or `${X...}` is none: what it
    holds would not be read off the text. Every word is kept, wherever it stands, since the order
    the lines run in is not the order they are written in."""
    lines = body.splitlines()
    words: dict[str, set[str]] = {}
    computed: set[str] = set()
    for line in lines:
        a = _ASSIGN.match(line)
        if a:
            if re.fullmatch(r"[A-Za-z0-9_.+-]+", a.group(3)):
                words.setdefault(a.group(1), set()).add(a.group(3))
            else:
                computed.add(a.group(1))
    out: dict[str, list[str]] = {}
    for name in sorted(set(words) - computed):
        mention = re.compile(rf"(?<!\w){re.escape(name)}(?!\w)")
        for line in lines:
            a = _ASSIGN.match(line)
            if a and a.group(1) == name:
                continue
            if any(not (line[: m.start()].endswith("$") or (line[: m.start()].endswith("${")
                                                             and not re.match(r":?=", line[m.end():])))
                   for m in mention.finditer(line)):
                break
        else:
            out[name] = sorted(words[name])
    return out


def cargo_calls(text: str) -> list[Call]:
    """Every cargo call of an executed shell text (see `Call`). A selector that is the variable
    of a `for` over literal words (`for crate in a b; do ... -p "$crate"`) names every word of
    every such `for` since the variable was last bound another way (a `read`, a `local`, an
    assignment, a `for` over anything else), a superset of what it holds; one the text binds only
    by plain assignments of a literal word names every such word (`_constant_words`). A call whose
    selector holds any other variable is unresolved and says why; a call inside a quoted string is read only when it names
    its packages, since an `echo` mentions cargo far more often than a `bash -c` runs it. The directory
    is a `cd` earlier on the call's line, or else the last line that is a `cd` alone (one inside a
    subshell starts with its parenthesis and is not read), with the text's plain assignments
    substituted."""
    out: list[Call] = []
    assigned: dict[str, str] = {}
    looped: dict[str, list[str]] = {}
    last_cd: str | None = None
    constant = _constant_words(executed(text))
    for line in executed(text).splitlines():
        a = _ASSIGN.match(line)
        if a:
            assigned[a.group(1)] = _expand(a.group(3), assigned)
        loop = _FOR.match(line)
        if loop:
            words = [_LITERAL_WORD.fullmatch(w) for w in loop.group(2).split()]
            if words and all(words):
                looped.setdefault(loop.group(1), []).extend(w.group(2) for w in words if w)
            else:
                looped.pop(loop.group(1), None)
        else:
            for name in list(looped):
                if re.match(rf"^\s*(?:local\s+|export\s+|readonly\s+)?{name}=", line) or (
                        _REBINDS.search(line) and re.search(rf"(?<![\w${{]){name}(?![\w}}])", line)):
                    looped.pop(name)
        bare = re.match(r"^\s*cd\s+[\"']?([^\s\"';&|)]+)[\"']?\s*$", line)
        if bare:
            last_cd = _expand(bare.group(1), assigned)
        for m in _CARGO.finditer(line):
            quoted = line[: m.start()].count('"') % 2 == 1
            toks = [t.strip("\"'") for t in m.group(2).split()]
            packages: list[str] = []
            manifest: str | None = None
            whole = False
            bad = ""
            i = 0
            while i < len(toks):
                tok = toks[i]
                value: str | None = None
                if tok in ("-p", "--package") and i + 1 < len(toks):
                    value = toks[i + 1]
                    i += 1
                elif tok.startswith("--package="):
                    value = tok.split("=", 1)[1]
                elif tok.startswith("-p") and len(tok) > 2 and not tok.startswith("--"):
                    value = tok[2:]
                elif tok == "--manifest-path" and i + 1 < len(toks):
                    manifest = _expand(toks[i + 1], assigned)
                    i += 1
                elif tok.startswith("--manifest-path="):
                    manifest = _expand(tok.split("=", 1)[1], assigned)
                elif tok in ("--workspace", "--all"):
                    whole = True
                if value is not None:
                    var = re.fullmatch(r"\$\{?([A-Za-z_]\w*)\}?", value)
                    if var and var.group(1) in looped:
                        packages.extend(looped[var.group(1)])
                    elif var and var.group(1) in constant:
                        packages.extend(constant[var.group(1)])
                    else:
                        packages.append(value)
                        if "$" in value or "`" in value or not value:
                            bad = f"cargo {m.group(1)} names its packages through a variable ({value or 'nothing'})"
                i += 1
            cds = _CD.findall(line[: m.start()])
            cwd = _expand(cds[-1], assigned) if cds else last_cd
            if quoted and not packages and manifest is None:
                continue
            out.append(Call(m.group(1), tuple(packages), manifest, whole, cwd, bad))
    return out


# -- one tree's context --------------------------------------------------------------------------


class Ctx(NamedTuple):
    tree: GitTree
    text: str
    #: each top-level function of the dispatch script, its definition without comments
    funcs: dict[str, str]
    #: the dispatch script's code outside its functions, without comments and dispatch lines
    preamble: str
    dispatch: dict[str, str]
    decls: dict[str, lane_decl.LaneDecl]
    hosted: dict[str, runci_plan.Hosted]
    dirs: set[str]
    spaces: dict[str, lane_graph.Workspace]
    #: the lanes whose entry is another tree's (`context(..., decls_from=...)`)
    borrowed: frozenset[str] = frozenset()
    #: why the dispatch script could not be split into its definitions ("" when it was)
    runci_error: str = ""


_CTX: dict[tuple[str, str], Ctx] = {}


def _hosted(tree: GitTree) -> dict[str, runci_plan.Hosted]:
    try:
        import yaml  # the planner's workflows are read with PyYAML, as runci_plan reads them
    except ImportError as err:
        raise DigestError(f"PyYAML is needed to read {', '.join(WORKFLOWS)}: {err}") from err
    docs = []
    for path in WORKFLOWS:
        text = tree.text(path)
        if text is None:
            continue
        try:
            docs.append(yaml.safe_load(text) or {})
        except yaml.YAMLError as err:
            raise DigestError(f"{path} at {tree.commit[:12]} does not parse: {err}") from err
    if not docs:
        raise DigestError(f"no hosted workflow ({', '.join(WORKFLOWS)}) at {tree.commit[:12]}")
    return runci_plan.hosted_runs(docs)


def context(root: Path, rev: str, *, decls_from: str | None = None) -> Ctx:
    """The tree of `rev` read once: its dispatch table, declaration, hosted jobs and workspaces.

    With `decls_from`, a lane the tree's own declaration has no entry for is declared by the
    entry of the tree of `decls_from` (see "Comparing two trees"); the tree's own entries stand."""
    commit = git(root, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").decode().strip()
    key = (str(Path(root).resolve()), commit)
    if key not in _CTX:
        _CTX[key] = _read_context(root, rev, commit)
    ctx = _CTX[key]
    if decls_from is None:
        return ctx
    lent = {lane: e for lane, e in context(root, decls_from).decls.items() if lane not in ctx.decls}
    return ctx._replace(decls={**ctx.decls, **lent}, borrowed=frozenset(lent)) if lent else ctx


def _read_context(root: Path, rev: str, commit: str) -> Ctx:
    tree = GitTree(root, commit)
    text = tree.text(RUNCI)
    if text is None:
        raise DigestError(f"{RUNCI} is not in the tree of {rev}")
    try:
        shell = parse_shell(text)
        funcs, preamble, error = shell.funcs, shell.top, ""
    except ShellParseError as err:
        funcs, preamble, error = {}, "", str(err)
    dispatch = {m.group(1): m.group(2) for m in runci_plan.DISPATCH.finditer(text)}
    entries, _findings = lane_decl.parse(tree.text(lane_decl.DECL_PATH) or "")
    dirs: set[str] = set()
    for path in tree.entries:
        parts = path.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    return Ctx(tree, text, funcs, preamble, dispatch, {e.id: e for e in entries}, _hosted(tree), dirs,
               lane_graph.workspaces(tree), runci_error=error)


# -- one lane's analysis -------------------------------------------------------------------------


class Analysis(NamedTuple):
    #: the spec's `runci`: the definitions the lane runs, or why the dispatch script is an input whole
    runci: dict
    scripts: dict[str, str]
    files: set[str]
    links: dict[str, str]
    lock: list[str]
    opaque: list[str]


def _split_id(lane_id: str) -> tuple[str, str | None]:
    lane, _, part = lane_id.partition(":")
    return lane, (part or None)


def _workspace_of(ctx: Ctx, directory: str) -> str | None:
    """The workspace root a directory is in: the deepest root holding it."""
    best = None
    for root in ctx.spaces:
        if directory == root or directory.startswith(root + "/") or root == "":
            if best is None or len(root) > len(best):
                best = root
    return best


def _clean_path(path: str) -> str | None:
    path = _ROOT_VARS.sub("", path)
    if "$" in path or "`" in path:
        return None
    return posixpath.normpath(path)


def _in_gitlink(ctx: Ctx, path: str) -> str | None:
    """The submodule gitlink a path lies in, or None."""
    return next((g for g in ctx.tree.gitlinks() if path == g or path.startswith(g + "/")), None)


def _resolve_call(ctx: Ctx, call: Call) -> tuple[list[tuple[str, str]], list[str], str]:
    """(the (workspace, package key) pairs a cargo call builds, the submodule gitlinks it builds
    in, why it cannot be read or "")."""
    if call.unresolved:
        return [], [], call.unresolved
    if call.manifest is not None:
        manifest = _clean_path(call.manifest)
        if manifest is None:
            return [], [], f"cargo {call.sub} --manifest-path {call.manifest} is computed"
        link = _in_gitlink(ctx, manifest)
        if link is not None:
            return [], [link], ""
        cwd = _clean_path(call.cwd) if call.cwd else None
        # A call with no `cd` this reader sees runs at the root or, through a helper that enters it
        # (`_runci_guarded_test`), in crates/; a manifest given relative to crates/ climbs out of it.
        tried = [posixpath.normpath(m) for m in
                 ([posixpath.join(cwd, manifest)] if cwd else []) + [manifest, f"crates/{manifest}"]]
        found = next((m for m in tried if m in ctx.tree.entries), None)
        if found is None:
            return [], [], f"cargo {call.sub} --manifest-path {call.manifest} names no tracked manifest"
        directory = posixpath.dirname(found)
        root = _workspace_of(ctx, directory)
        if root is None:
            return [], [], f"{found} is in no workspace with a lock"
        ws = ctx.spaces[root]
        if call.packages:
            pairs = [(root, k) for name in call.packages for k in ws.find(name)]
        else:
            name = lane_graph.package_name(ctx.tree.text(found) or "")
            pairs = [(root, k) for k in (ws.members if (name is None or call.whole) else ws.find(name))]
        return (pairs, [], "") if pairs else ([], [], f"{found} builds no package of {root}/Cargo.lock")
    cwd = _clean_path(call.cwd) if call.cwd else None
    if call.packages:
        # In a directory of a workspace that has the package, cargo builds it there; elsewhere the
        # package is read where it is a member.
        here = _workspace_of(ctx, cwd) if cwd else None
        local = ctx.spaces[here] if here is not None else None
        pairs: list[tuple[str, str]] = []
        missing: list[str] = []
        for name in call.packages:
            got = [(here, k) for k in local.find(name) if not local.packages[k].source] if local else []
            got = got or lane_graph.resolve(ctx.spaces, name)
            pairs.extend(got)
            if not got:
                missing.append(name)
        if missing:
            return [], [], f"cargo {call.sub} -p {', '.join(missing)}: no workspace has the package"
        return pairs, [], ""
    if cwd is None:
        return [], [], f"cargo {call.sub} with no package and no directory this reader can see"
    link = _in_gitlink(ctx, cwd)
    if link is not None:
        return [], [link], ""
    root = _workspace_of(ctx, cwd)
    if root is None:
        return [], [], f"cargo {call.sub} in {cwd}, which is in no workspace with a lock"
    ws = ctx.spaces[root]
    if cwd == root or call.whole:
        return [(root, k) for k in ws.members], [], ""
    name = lane_graph.package_name(ctx.tree.text(f"{cwd}/Cargo.toml") or "")
    pairs = [(root, k) for k in ws.find(name)] if name else []
    return (pairs, [], "") if pairs else ([], [], f"cargo {call.sub} in {cwd}, which is no package of {root}")


_ANALYSIS: dict[tuple[str, str, bytes], Analysis] = {}


def analyse(ctx: Ctx, lane: str) -> Analysis:
    """What lane `lane` runs and reads at this tree (see the module docstring), once per tree
    and entry: a tree read with another tree's entry for the lane is another analysis."""
    entry = ctx.decls.get(lane)
    key = (ctx.tree.commit, lane, b"" if entry is None else _canon(lane_decl.canonical(entry)))
    if key not in _ANALYSIS:
        _ANALYSIS[key] = _analyse(ctx, lane)
    return _ANALYSIS[key]


def _analyse(ctx: Ctx, lane: str) -> Analysis:
    if lane not in ctx.dispatch:
        raise DigestError(f"lane {lane} is not in the dispatch table of {RUNCI} at {ctx.tree.commit[:12]}")
    entry = ctx.decls.get(lane)
    if entry is None:
        raise DigestError(f"lane {lane} has no readable entry in {lane_decl.DECL_PATH} at {ctx.tree.commit[:12]}")
    fn = ctx.dispatch[lane]
    # Why the dispatch script is an input whole (see "The dispatch script"); empty when the lane's
    # key holds only the definitions it runs.
    whole: list[str] = []
    if ctx.runci_error:
        whole.append(f"it does not split into its definitions ({ctx.runci_error})")
    elif fn not in ctx.funcs:
        whole.append(f"it defines no function {fn} this reader found")
    runci: dict
    if whole:
        runci = {"unit": "file"}
        texts = [ctx.text]
    else:
        seeds = {fn, "run_layer"} | set(_WORD.findall(executed(ctx.preamble)))
        functions = function_closure(ctx.funcs, seeds)
        runci = {"unit": "definitions", "top": _sha(ctx.preamble),
                 "defs": [[n, _sha(ctx.funcs[n])] for n in functions]}
        texts = [ctx.preamble] + [ctx.funcs[n] for n in functions]
    tree = ctx.tree
    gitlinks = tree.gitlinks()
    opaque: list[str] = []
    unresolved: list[str] = []
    scripts: dict[str, str] = {}
    files: set[str] = set()
    links: dict[str, str] = {}
    named_dirs: set[str] = set()
    builds: dict[str, set[str]] = {}
    # (text, the directory of its file, its kind for `names_in`, its path, the options its call
    # sites pass or None for every mode, the names its importers use when it is imported and not
    # run); the dispatch script is in scripts/ and runs from the root, so a name in it is tried
    # against both.
    queue: list[tuple[str, str, str, str, frozenset[str] | None, frozenset[str] | None]] = [
        (text, "scripts", "shell", RUNCI, None, None) for text in texts]
    # The modes each script has been read in; a call site that adds one reads it again.
    modes_read: dict[str, frozenset[str] | None] = {}
    # The names each module imported and not run has been read for; an importer that uses
    # another reads it again.
    names_read: dict[str, frozenset[str]] = {}
    reads_graph = False
    # Every unit runs through the planner; a tree without one (a selftest's) has nothing to add.
    for path in ([PLANNER] if PLANNER in tree.entries else []) + ([entry.legs] if entry.legs else []):
        if path not in tree.entries:
            opaque.append(f"{path} is named by the lane's entry and is not in the tree")
            continue
        scripts[path] = tree.entries[path].oid
        modes_read[path] = None
        kind = "code" if path == PLANNER else ("python" if path.endswith(".py") else "shell")
        queue.append(((tree.text(path) or ""), posixpath.dirname(path), kind, path, None, None))
    while queue:
        text, base, kind, where, modes, used = queue.pop()
        body = executed(text)
        if kind == "python":
            refs = python_refs(text, modes, used)
            if refs is None:
                unresolved.append(f"{where} does not parse as python, so what it spawns is unknown")
            else:
                spawned: set[str] = set()
                for sub, words in refs.cargo:
                    if sub in CARGO_READS:
                        reads_graph = True
                    elif sub in CARGO_ASKS:
                        continue
                    else:
                        # A list of constants is the shell call it spells; its cwd is unknown.
                        plain = sub != "?" and words is not None and all(_PLAIN_WORD.fullmatch(w) for w in words)
                        calls = cargo_calls("cargo " + " ".join(words or ())) if plain else []
                        if not calls:
                            spawned.add(sub)
                        for call in calls:
                            got, call_links, why = _resolve_call(ctx, call)
                            for root, key in got:
                                builds.setdefault(root, set()).add(key)
                            for link in call_links:
                                links[link] = gitlinks[link]
                            if why:
                                spawned.add(sub)
                if spawned:
                    unresolved.append(f"{where} spawns cargo {', '.join(sorted(spawned))} from an argv list")
            if refs is not None and refs.runs_lane:
                unresolved.append(f"{where} runs another lane of run-ci.sh")
        elif kind == "shell":
            if re.search(r"run-ci\.sh\s+--layer", body):
                unresolved.append("it runs another lane of run-ci.sh")
            if _SPAWNS_CARGO.search(body):
                unresolved.append("a text it runs spawns cargo from an argv list")
            for call in cargo_calls(text):
                if call.sub in CARGO_READS:
                    reads_graph = True
                    continue
                got, call_links, why = _resolve_call(ctx, call)
                for root, key in got:
                    builds.setdefault(root, set()).add(key)
                for link in call_links:
                    links[link] = gitlinks[link]
                if why:
                    unresolved.append(why)
        named = names_in(text, base, tree, ctx.dirs, kind, modes, used)
        for link in named.links:
            links[link] = gitlinks[link]
        named_dirs |= named.dirs
        files |= named.files
        if RUNCI in named.files:
            whole.append(f"{where} reads it")
        # A module imported whose use is not read may run any of its code, as a script spawned does.
        for path in sorted(named.scripts | {p for p, n in named.imported.items() if n is None}):
            if path == RUNCI:
                # Another lane of it run whole, or the script read by a command of a shell text.
                whole.append(f"a text of {where} names it (another lane run whole, or the script read)")
                continue
            data = tree.read(path) or b""
            script = data.decode("utf-8", "replace")
            is_python = path.endswith(".py") or data.startswith(b"#!/usr/bin/env python")
            sub = "code" if kind == "code" else ("python" if is_python else "shell")
            # A shell line that runs a python script says which of its modes runs; anything else
            # (an import, a spawn, a declaration) may run any.
            mode = call_modes(text, path, py_options(script)) if kind == "shell" and sub == "python" else None
            if path in modes_read:
                before = modes_read[path]
                if before is None or (mode is not None and mode <= before):
                    continue
                mode = None if mode is None else before | mode
            modes_read[path] = mode
            scripts[path] = tree.entries[path].oid
            queue.append((script, posixpath.dirname(path), sub, path, mode, None))
        for path, names in sorted(named.imported.items(), key=lambda item: item[0]):
            if names is None or modes_read.get(path, frozenset()) is None:
                continue
            before = names_read.get(path)
            if before is not None and names <= before:
                continue
            names = names if before is None else before | names
            names_read[path] = names
            scripts[path] = tree.entries[path].oid
            queue.append(((tree.read(path) or b"").decode("utf-8", "replace"), posixpath.dirname(path),
                          "python", path, None, names))
    for d in named_dirs:
        for path in tree.under(d):
            if path in gitlinks:
                links[path] = gitlinks[path]
            else:
                files.add(path)
    for pattern in entry.decl:
        for path in tree.glob(pattern):
            if path in gitlinks:
                links[path] = gitlinks[path]
            else:
                files.add(path)
    for spec in entry.packages:
        got = lane_graph.resolve(ctx.spaces, spec)
        if not got:
            opaque.append(f"declared package {spec} resolves to no package")
        for root, key in got:
            builds.setdefault(root, set()).add(key)
    if entry.legs and entry.legs in tree.entries:
        try:
            for name in lane_decl.leg_packages(tree.text(entry.legs) or ""):
                got = lane_graph.resolve(ctx.spaces, name)
                if not got:
                    opaque.append(f"leg package {name} of {entry.legs} resolves to no package")
                for root, key in got:
                    builds.setdefault(root, set()).add(key)
        except ValueError as err:
            opaque.append(f"{entry.legs}: {err}")
    if reads_graph:
        graph_paths, graph_links = lane_graph.manifest_inputs(tree)
        files |= graph_paths
        links.update(graph_links)
    # A declaration of what the lane builds stands for the calls this reader cannot read.
    if unresolved and not (entry.packages or entry.legs):
        opaque.extend(unresolved)
    lock: set[str] = set()
    for root, keys in sorted(builds.items()):
        paths, ws_links, entries = lane_graph.inputs(tree, ctx.spaces[root], keys)
        files |= paths
        links.update(ws_links)
        lock.update(f"{root}: {e}" for e in entries)
    if RUNCI in files and not whole:
        whole.append("a directory or a declared glob the lane reads holds it")
    if whole:
        files.add(RUNCI)
        runci = {**runci, "unit": "file", "why": sorted(set(whole))}
    return Analysis(runci, scripts, files, links, sorted(lock), sorted(set(opaque)))


# -- the machine -----------------------------------------------------------------------------------


def _ask(argv: list[str]) -> str:
    """A program's stdout, or `unavailable: ...` when it does not answer; never an install."""
    env = dict(os.environ, RUSTUP_AUTO_INSTALL="0")
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False, env=env)
    except (OSError, subprocess.TimeoutExpired) as err:
        return f"unavailable: {type(err).__name__}"
    if done.returncode != 0:
        return f"unavailable: rc={done.returncode}"
    return done.stdout.strip()


_MACHINE: dict[str | None, dict[str, str]] = {}


def machine_reader(channel: str | None) -> dict[str, str]:
    """What this machine reports (see the module docstring). A tool that does not answer is
    recorded as unavailable, which is a value of the key like any other."""
    if channel not in _MACHINE:
        plus = [f"+{channel}"] if channel else []
        try:
            machine = _sha(Path("/etc/machine-id").read_bytes().strip())
        except OSError:
            machine = "unavailable"
        _MACHINE[channel] = {
            "rustc": _ask(["rustc", *plus, "-vV"]),
            "cargo": _ask(["cargo", *plus, "-V"]),
            "cc": (_ask(["cc", "--version"]).splitlines() or [""])[0],
            "python": _ask(["python3", "--version"]),
            "machine": machine,
        }
    return _MACHINE[channel]


def _env(ctx: Ctx, entry: lane_decl.LaneDecl, reader: EnvReader) -> dict:
    tree = ctx.tree
    toolchain = tree.text(TOOLCHAIN) or ""
    m = re.search(r'(?m)^\s*channel\s*=\s*"([^"]+)"', toolchain)
    channel = m.group(1) if m else None
    bx = tree.text(BX_TOML) or ""
    tools = "\n".join(re.findall(r"(?ms)^\[tools\.[^\]]+\]\n.*?(?=^\[|\Z)", bx))
    upstream = re.search(r"(?m)^UPSTREAM_VERSION\s*=.*$", tree.text(UPSTREAM) or "")
    pin = tree.entries.get(ORACLE_PIN)
    machine = dict(reader(channel))
    if entry.cls != "E":
        machine.pop("machine", None)
    return {
        "toolchain": tree.entries[TOOLCHAIN].oid if TOOLCHAIN in tree.entries else None,
        "tools": _sha(tools),
        "oracle_pin": pin.oid if pin else None,
        "upstream_version": upstream.group(0) if upstream else None,
        "machine": machine,
    }


# -- the public functions --------------------------------------------------------------------------


_ASKS: dict[str, dict[str, runci_plan.Asks]] = {}


def _unit(ctx: Ctx, lane: str, part: str | None) -> dict:
    """The planner's unit for the lane (or one part of it), as `bx --checks ci` receives it."""
    if ctx.tree.commit not in _ASKS:
        _ASKS[ctx.tree.commit] = runci_plan.lane_asks(ctx.text, runci_plan.lane_commands(), runci_plan.LANE_PACKAGES)
    return runci_plan.unit(lane, _ASKS[ctx.tree.commit].get(lane, runci_plan.Asks()), part)


def record(root: Path, rev: str, lane_id: str, *, env_reader: EnvReader | None = None,
           decls_from: str | None = None) -> dict:
    ctx = context(root, rev, decls_from=decls_from)
    lane, part = _split_id(lane_id)
    a = analyse(ctx, lane)
    entry = ctx.decls[lane]
    hosted = ctx.hosted.get(lane)
    spec = {
        "lane": lane,
        "part": part,
        "fn": ctx.dispatch[lane],
        "decl": lane_decl.canonical(entry),
        "unit": _unit(ctx, lane, part),
        "hosted": None if hosted is None else {"env": hosted.env, "prep": [[e, argv] for e, argv in hosted.prep]},
        "runci": a.runci,
        "scripts": sorted([p, oid] for p, oid in a.scripts.items()),
    }
    tree = ctx.tree
    if a.opaque:
        files = sorted([p, e.mode, e.oid] for p, e in tree.entries.items() if e.kind == "blob")
        links = sorted([p, c] for p, c in tree.gitlinks().items())
        lock: list[str] = []
    else:
        files = sorted([p, tree.entries[p].mode, tree.entries[p].oid] for p in a.files if p in tree.entries)
        links = sorted([p, c] for p, c in a.links.items())
        lock = a.lock
    return {
        "schema": SCHEMA,
        "lane": lane_id,
        "opaque": a.opaque,
        "spec": spec,
        "env": _env(ctx, entry, env_reader or machine_reader),
        "inputs": {"files": files, "gitlinks": links, "lock": lock},
    }


def digest(root: Path, rev: str, lane_id: str, *, env_reader: EnvReader | None = None,
           decls_from: str | None = None) -> str:
    return digest_of(record(root, rev, lane_id, env_reader=env_reader, decls_from=decls_from))


@contextlib.contextmanager
def _checkout(root: Path, tree: GitTree) -> Iterator[Path]:
    """A directory holding `tree`'s files: `root` itself when its HEAD is that tree and nothing
    tracked is modified, else the tree unpacked into a temporary directory."""
    head = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    dirty = git(root, "status", "--porcelain", "--untracked-files=no").strip()
    if head == tree.tree and not dirty:
        yield Path(root)
        return
    with tempfile.TemporaryDirectory(prefix="wz-lane-digest-") as tmp:
        data = git(root, "archive", "--format=tar", tree.commit)
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            kwargs = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
            tar.extractall(tmp, **kwargs)
        yield Path(tmp)


def lanes(root: Path, rev: str, *, tables: dict | None = None, decls_from: str | None = None) -> list[dict]:
    ctx = context(root, rev, decls_from=decls_from)
    tables = tables if tables is not None else {}
    parted = tables.get("parted")
    listing = parted if parted is not None else runci_plan.PARTED_LANES
    with contextlib.ExitStack() as stack:
        if listing:
            where = stack.enter_context(_checkout(Path(root), ctx.tree))
            stack.enter_context(_chdir(where))
        try:
            units = runci_plan.plan(ctx.text, None, ctx.hosted, tables.get("commands"),
                                    tables.get("packages"), parted)
        except ValueError as err:
            raise DigestError(f"the planner refuses the tree of {rev}: {err}") from err
    undeclared = sorted({u["name"].split(":")[0] for u in units} - set(ctx.decls))
    if undeclared and decls_from is None:
        raise DigestError(f"lane(s) with no readable entry in {lane_decl.DECL_PATH}: {', '.join(undeclared)}")
    # Neither tree declares these, so the lane set of `decls_from` (whose own read refuses an
    # undeclared lane) holds none of them, and no comparison with it asks about them.
    units = [u for u in units if _split_id(u["name"])[0] in ctx.decls]
    out: list[dict] = []
    for u in units:
        lane, part = _split_id(u["name"])
        out.append({
            "id": u["name"],
            "lane": lane,
            "part": part,
            "class": ctx.decls[lane].cls,
            "opaque": bool(analyse(ctx, lane).opaque),
            "unit": u,
        })
    return out


@contextlib.contextmanager
def _chdir(path: Path) -> Iterator[None]:
    before = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(before)


def _runci_lines(before: dict, after: dict) -> list[str]:
    """What `explain` says of the dispatch script: why it is an input whole, and which of the
    definitions the lane runs differ."""
    out: list[str] = []
    if after["unit"] == "file":
        out.append(f"  {RUNCI} is an input whole: {'; '.join(after.get('why', []))}")
    old = {name: sha for name, sha in before.get("defs", [])}
    new = {name: sha for name, sha in after.get("defs", [])}
    for word, names in (("changed", sorted(n for n in new if n in old and old[n] != new[n])),
                        ("added", sorted(n for n in new if n not in old)),
                        ("removed", sorted(n for n in old if n not in new))):
        if names:
            out.append(f"  {RUNCI} definitions {word}: {', '.join(names)}")
    if "top" in before and "top" in after and before["top"] != after["top"]:
        out.append(f"  {RUNCI} code outside its functions changed (every lane runs it)")
    return out


def explain(root: Path, base: str, head: str, lane_id: str, *, env_reader: EnvReader | None = None) -> str:
    after = record(root, head, lane_id, env_reader=env_reader)
    d_after = digest_of(after)
    try:
        before = record(root, base, lane_id, env_reader=env_reader, decls_from=head)
    except DigestError as err:
        return f"{lane_id}: selected -- it has no digest at {base} ({err}); D at {head} is {d_after}"
    d_before = digest_of(before)
    lent = _split_id(lane_id)[0] in context(root, base, decls_from=head).borrowed
    note = [f"  {base} has no entry for the lane in {lane_decl.DECL_PATH}: read with {head}'s"] if lent else []
    if d_before == d_after:
        return "\n".join([f"{lane_id}: not selected -- D is {d_after} at both {base} and {head}", *note])
    lines = [f"{lane_id}: selected -- D moves from {d_before} at {base} to {d_after} at {head}", *note]
    if after["opaque"]:
        lines.append(f"  opaque (its inputs are the whole tree): {'; '.join(after['opaque'])}")
    for part in ("spec", "env"):
        changed = sorted(k for k in set(before[part]) | set(after[part]) if before[part].get(k) != after[part].get(k))
        if changed:
            lines.append(f"  {part} differs in: {', '.join(changed)}")
    lines.extend(_runci_lines(before["spec"]["runci"], after["spec"]["runci"]))
    for kind in ("files", "gitlinks", "lock"):
        old = {json.dumps(x) for x in before["inputs"][kind]}
        new = {json.dumps(x) for x in after["inputs"][kind]}
        if kind == "lock":
            added, removed, changed_paths = sorted(new - old), sorted(old - new), []
        else:
            old_paths = {json.loads(x)[0]: x for x in old}
            new_paths = {json.loads(x)[0]: x for x in new}
            added = sorted(p for p in new_paths if p not in old_paths)
            removed = sorted(p for p in old_paths if p not in new_paths)
            changed_paths = sorted(p for p in new_paths if p in old_paths and old_paths[p] != new_paths[p])
        for word, items in (("changed", changed_paths), ("added", added), ("removed", removed)):
            if items:
                shown = ", ".join(items[:40]) + (f" and {len(items) - 40} more" if len(items) > 40 else "")
                lines.append(f"  {kind} {word} ({len(items)}): {shown}")
    return "\n".join(lines)


def select(root: Path, base: str, head: str, *, env_reader: EnvReader | None = None,
           tables: dict | None = None) -> list[str]:
    out: list[str] = []
    for u in lanes(root, head, tables=tables):
        try:
            before = digest(root, base, u["id"], env_reader=env_reader, decls_from=head)
        except DigestError:
            out.append(u["id"])
            continue
        if before != digest(root, head, u["id"], env_reader=env_reader):
            out.append(u["id"])
    return out


# -- the selftest ---------------------------------------------------------------------------------

_RUNCI_FIXTURE = """#!/usr/bin/env bash
# a dispatch table of four lanes over lane_graph's fixture workspace
overall=0
run_layer() {
    "$2" || return 1
    python3 scripts/lib/reader.py --read --lane "$1"
}
_fixture_helper() {
    echo helper
}
layer_c_app() {
    _fixture_helper
    (cd crates && cargo test -p app) || return 1
}
layer_g_gate() {
    python3 scripts/lib/gate.py || return 1
    cat <<'EOF'
}
{ a brace a heredoc holds
EOF
    echo "}" '{' "${FIXTURE_UNSET:-}}"
}
layer_o_opaque() {
    local pkg="$1"
    (cd crates && cargo test -p "$pkg") || return 1
}
layer_w_workspace() {
    (cd crates && cargo test --workspace) || return 1
}
layer_b_build() {
    python3 scripts/lib/build.py || return 1
}
layer_p_computed() {
    python3 scripts/lib/computed.py || return 1
}
layer_r_graph() {
    python3 scripts/lib/graph.py || return 1
}
layer_a_audit() {
    python3 scripts/lib/reader.py --audit || return 1
}
run_layer C layer_c_app || overall=1
run_layer G layer_g_gate || overall=1
run_layer O layer_o_opaque || overall=1
run_layer W layer_w_workspace || overall=1
run_layer B layer_b_build || overall=1
run_layer P layer_p_computed || overall=1
run_layer R layer_r_graph || overall=1
run_layer A layer_a_audit || overall=1
exit "$overall"
"""

_DECL_FIXTURE = """schema = "wz-lanes/1"

[[lane]]
id = "C"
fn = "layer_c_app"
class = "D"

[[lane]]
id = "G"
fn = "layer_g_gate"
class = "D"
decl = ["docs/notes/**"]

[[lane]]
id = "O"
fn = "layer_o_opaque"
class = "D"

[[lane]]
id = "W"
fn = "layer_w_workspace"
class = "E"
reason = "the fixture's machine"

[[lane]]
id = "B"
fn = "layer_b_build"
class = "D"

[[lane]]
id = "P"
fn = "layer_p_computed"
class = "D"

[[lane]]
id = "R"
fn = "layer_r_graph"
class = "D"

[[lane]]
id = "A"
fn = "layer_a_audit"
class = "D"
"""

_CI_FIXTURE = """on: push
jobs:
  all:
    runs-on: ubuntu-22.04
    steps:
      - run: bash scripts/run-ci.sh --layer C
      - run: bash scripts/run-ci.sh --layer G
      - run: bash scripts/run-ci.sh --layer O
      - run: bash scripts/run-ci.sh --layer W
      - run: bash scripts/run-ci.sh --layer B
      - run: bash scripts/run-ci.sh --layer P
      - run: bash scripts/run-ci.sh --layer R
      - run: bash scripts/run-ci.sh --layer A
"""

#: A script the dispatch runs for every lane in one mode (`--read`) and for lane A in another
#: (`--audit`), which alone reads the dispatch script.
_READER_FIXTURE = '''import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def audit() -> int:
    return len((ROOT / "scripts" / "run-ci.sh").read_text().splitlines())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--read", action="store_true")
    ap.add_argument("--audit", action="store_true")
    ap.add_argument("--lane")
    args = ap.parse_args()
    if args.audit:
        return audit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

FIXTURE: dict[str, str] = {
    **lane_graph.FIXTURE,
    RUNCI: _RUNCI_FIXTURE,
    lane_decl.DECL_PATH: _DECL_FIXTURE,
    WORKFLOWS[0]: _CI_FIXTURE,
    "scripts/lib/gate.py": 'import helper\n\nTABLE = "deploy/table.json"\n',
    # A module imported for a name, with a build no importer reaches: its own computed cargo call
    # runs only when `build` is called.
    "scripts/lib/helper.py": 'import subprocess\nimport sys\n\nX = 1\n\n\ndef build() -> None:\n'
                             '    subprocess.run(["cargo", "build", "-p", sys.argv[1]], check=True)\n',
    "scripts/lib/build.py": 'import subprocess\n\nsubprocess.run(["cargo", "build", "-p", "core"], check=True)\n',
    "scripts/lib/computed.py": 'import subprocess\nimport sys\n\nsubprocess.run(["cargo", "build", "-p", sys.argv[1]], check=True)\n',
    "scripts/lib/graph.py": 'import subprocess\n\nsubprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1"], check=True)\n',
    "scripts/lib/reader.py": _READER_FIXTURE,
    "crates/core/src/inner.rs": "pub fn i() {}\n",
    "deploy/table.json": "{}\n",
    "docs/notes/a.md": "a\n",
    "docs/other.md": "other\n",
}


def selftest() -> int:
    cases = 0

    def expect(name: str, ok: bool, detail: object = "") -> None:
        nonlocal cases
        if not ok:
            raise AssertionError(f"lane_digest selftest: {name} FAILED {detail}")
        cases += 1

    machine = {"rustc": "rustc 1.0.0 (fixture)", "cargo": "cargo 1.0.0", "cc": "cc", "python": "Python 3", "machine": "m1"}

    def reader(channel: str | None) -> dict[str, str]:
        return dict(machine)

    tables = {"commands": {}, "packages": {}, "parted": {}}
    with Fixture() as fx:
        revs = [fx.commit(FIXTURE, lane_graph.FIXTURE_LINKS)]
        root = fx.root

        def d(rev: str, lane: str) -> str:
            return digest(root, rev, lane, env_reader=reader)

        def step(files: dict[str, str | None], links: dict[str, str | None] | None = None) -> tuple[str, str]:
            before = revs[-1]
            revs.append(fx.commit(files, links))
            return before, revs[-1]

        def moved(pair: tuple[str, str], lane: str) -> bool:
            return d(pair[0], lane) != d(pair[1], lane)

        first = revs[0]
        got = lanes(root, first, tables=tables)
        expect("G(t) is the dispatch table's lanes, each unit named by its id",
               [(u["id"], u["class"], u["unit"]["name"]) for u in got]
               == [("C", "D", "C"), ("G", "D", "G"), ("O", "D", "O"), ("W", "E", "W"), ("B", "D", "B"),
                   ("P", "D", "P"), ("R", "D", "R"), ("A", "D", "A")], got)
        # Red if a python argv list of constants, or one that reads the graph, is called opaque, or
        # one whose package is computed is not, or if the computed build of a module G's script
        # imports and never calls makes G opaque (`_lib_reached`).
        expect("only the lanes whose packages are computed are opaque", [u["id"] for u in got if u["opaque"]] == ["O", "P"], got)
        # Red if `_resolve_call` stops normalising the crates/-relative manifest it tries.
        ctx = context(root, first)
        pairs, _links, why = _resolve_call(ctx, Call("test", (), "../tool/Cargo.toml", False, None, ""))
        expect("a manifest given relative to crates/ is found above it",
               why == "" and [ctx.spaces[r].packages[k].name for r, k in pairs] == ["tool"], (pairs, why))
        rec = record(root, first, "C", env_reader=reader)
        expect("a record recomputes its own digest", digest_of(rec) == d(first, "C"))
        expect("the digest is 64 hex digits", re.fullmatch(r"[0-9a-f]{64}", d(first, "C")) is not None)
        # Red if the D lane's key carries the machine (`_env` stops dropping it for D).
        expect("a D lane's key holds no machine identity", "machine" not in rec["env"]["machine"], rec["env"])
        expect("an E lane's key holds it", record(root, first, "W", env_reader=reader)["env"]["machine"].get("machine") == "m1")
        expect("the helper function the lane calls is in its spec",
               "_fixture_helper" in [n for n, _ in rec["spec"]["runci"]["defs"]], rec["spec"]["runci"])

        # Each change below is one commit; each assertion names what, if broken, turns it red.
        outside = step({"README.md": "changed\n", "docs/other.md": "changed\n"})
        # Red if `inputs` hashes the whole tree for a lane that is not opaque.
        expect("a file outside every input set moves no transparent lane",
               not any(moved(outside, lane) for lane in ("C", "G", "W", "B", "R")))
        # Red if an opaque lane's inputs stop being the whole tree.
        expect("an opaque lane moves on any change", moved(outside, "O"))
        dep = step({"crates/core/src/lib.rs": "pub fn f() { }\n"})
        # Red if `lane_graph.inputs` drops the closure's files.
        expect("a dependency crate's file moves the lane", moved(dep, "C"))
        devdep = step({"crates/support/src/lib.rs": "pub fn h() { }\n"})
        expect("the lane's own dev dependency moves it", moved(devdep, "C"))
        dev_of_dep = step({"crates/leaf/src/lib.rs": "pub fn g() { }\n"})
        # Red if `lane_graph.closure` follows a dependency's dev edges.
        expect("a dependency's dev dependency does not move it", not moved(dev_of_dep, "C"))
        expect("a lane over the whole workspace (after a cd) is moved by it", moved(dev_of_dep, "W"))
        pin = step({}, {"vendor/sub": "2" * 40})
        # Red if the closure's gitlinks leave M(L, t).
        expect("a submodule pointer the closure builds moves the lane", moved(pin, "C"))
        expect("a submodule pointer moves no lane that does not build it", not moved(pin, "G"))
        tool = step({"rust-toolchain.toml": '[toolchain]\nchannel = "1.0.1"\n'})
        # Red if the toolchain pin leaves both the workspace files and env.
        expect("the toolchain pin moves a cargo lane", moved(tool, "C"))
        lock = FIXTURE["crates/Cargo.lock"]
        other = step({"crates/Cargo.lock": lock.replace('checksum = "aa"', 'checksum = "a2"')})
        # Red if the lock is hashed whole instead of projected onto the closure.
        expect("a lock entry outside the closure does not move the lane", not moved(other, "C"))
        reg = step({"crates/Cargo.lock": lock.replace('checksum = "aa"', 'checksum = "a2"').replace('checksum = "bb"', 'checksum = "b2"')})
        expect("a lock entry inside the closure moves it", moved(reg, "C"))
        data = step({"deploy/table.json": "{\"x\": 1}\n"})
        # Red if `names_in` stops reading paths named in an executed script.
        expect("a data file a lane's script names moves that lane", moved(data, "G") and not moved(data, "C"))
        declared = step({"docs/notes/a.md": "b\n"})
        # Red if the `decl` globs leave the inputs.
        expect("a file a lane declares moves it", moved(declared, "G") and not moved(declared, "C"))
        imported = step({"scripts/lib/helper.py": "X = 2\n"})
        # Red if python imports leave the script closure.
        expect("a module a lane's script imports moves it", moved(imported, "G") and not moved(imported, "C"))
        inner = step({"crates/core/src/inner.rs": "pub fn i() { }\n"})
        # Red if a python argv list of constants is not read as the cargo call it spells.
        expect("a package a script's constant argv builds moves its lane", moved(inner, "B") and moved(inner, "C"))
        # Red if a graph read hashes the packages' sources instead of their manifests.
        expect("a source that decides no target does not move a lane that reads the graph", not moved(inner, "R"))
        manifest = step({"tool/Cargo.toml": FIXTURE["tool/Cargo.toml"] + "\n[features]\nx = []\n"})
        # Red if `lane_graph.manifest_inputs` leaves out a workspace the call may ask.
        expect("any workspace's manifest moves a lane that reads the graph", moved(manifest, "R"))
        expect("and no lane that builds in another workspace", not moved(manifest, "C") and not moved(manifest, "B"))
        body = step({RUNCI: _RUNCI_FIXTURE.replace("cargo test -p app)", "cargo test -p app --quiet)")})
        # Red if the spec holds run-ci.sh whole instead of the lane's own text.
        expect("a lane's own function moves it and no other lane", moved(body, "C") and not moved(body, "G"))
        runci_text = _RUNCI_FIXTURE.replace("cargo test -p app)", "cargo test -p app --quiet)").replace("echo helper", "echo helper2")
        helper = step({RUNCI: runci_text})
        expect("a function the lane calls moves it", moved(helper, "C") and not moved(helper, "G"))
        # Every lane's run_layer runs reader.py --read; lane A alone runs its --audit, which reads
        # run-ci.sh. Red if `call_modes` or `_py_reached` stop narrowing: every lane would hold the file.
        held = record(root, helper[1], "C", env_reader=reader)
        expect("a lane whose scripts do not read run-ci.sh holds its definitions, not the file",
               held["spec"]["runci"]["unit"] == "definitions"
               and RUNCI not in {f[0] for f in held["inputs"]["files"]}, held["spec"]["runci"])
        audit = record(root, helper[1], "A", env_reader=reader)
        expect("a lane whose script reads run-ci.sh in the mode it runs holds the file, and says why",
               audit["spec"]["runci"]["unit"] == "file" and RUNCI in {f[0] for f in audit["inputs"]["files"]}
               and audit["spec"]["runci"]["why"] == ["scripts/lib/reader.py reads it"], audit["spec"]["runci"])
        # Red if the code outside the functions leaves a lane's key.
        topped_text = runci_text.replace("overall=0\n", "overall=0\nexport FIXTURE_TOP=1\n")
        topped = step({RUNCI: topped_text})
        expect("code outside the functions moves every lane",
               topped_text != runci_text and all(moved(topped, lane) for lane in ("C", "G", "W", "B", "R", "A")))
        text = explain(root, topped[0], topped[1], "C", env_reader=reader)
        expect("explain names a change outside the functions", "outside its functions changed" in text, text)
        # Red if comments are hashed: a lane would move on a word the shell never runs.
        noted_text = topped_text.replace("    _fixture_helper\n", "    # the helper\n    _fixture_helper\n")
        noted = step({RUNCI: noted_text})
        expect("a comment moves only the lane that reads the file",
               noted_text != topped_text and not moved(noted, "C") and not moved(noted, "G") and moved(noted, "A"))
        # Red if a brace in a heredoc or a string ends a function: G's tail would be code outside.
        doc_text = noted_text.replace("{ a brace a heredoc holds", "{ another brace a heredoc holds")
        doc = step({RUNCI: doc_text})
        expect("a heredoc of a lane's function moves that lane alone",
               doc_text != noted_text and moved(doc, "G") and not moved(doc, "C") and not moved(doc, "W"))
        text = explain(root, doc[0], doc[1], "G", env_reader=reader)
        expect("explain names the definition that changed", "definitions changed: layer_g_gate" in text, text)
        # Red if a script that does not split is read as definitions anyway, or silently.
        broken = step({RUNCI: doc_text + "cat <<NEVER\nno end\n"})
        unsplit = record(root, broken[1], "C", env_reader=reader)
        expect("a dispatch script that does not split is an input whole, and says why",
               unsplit["spec"]["runci"]["unit"] == "file" and RUNCI in {f[0] for f in unsplit["inputs"]["files"]}
               and any("heredoc" in why for why in unsplit["spec"]["runci"]["why"]), unsplit["spec"]["runci"])
        text = explain(root, broken[0], broken[1], "G", env_reader=reader)
        expect("explain says the dispatch script is an input whole", f"{RUNCI} is an input whole" in text, text)
        step({RUNCI: runci_text})
        cls = step({lane_decl.DECL_PATH: _DECL_FIXTURE.replace('fn = "layer_c_app"\nclass = "D"', 'fn = "layer_c_app"\nclass = "E"\nreason = "r"')})
        # Red if the declaration entry leaves the spec.
        expect("a lane's declaration moves it", moved(cls, "C") and not moved(cls, "G"))
        machine["rustc"] = "rustc 1.0.0 (another build)"
        # Red if the machine's toolchain leaves env.
        expect("the machine's compiler moves every lane", d(cls[1], "C") != digest(root, cls[1], "C", env_reader=lambda c: dict(machine, rustc="rustc 1.0.0 (fixture)")))
        machine["rustc"] = "rustc 1.0.0 (fixture)"
        before_m = d(cls[1], "G")
        machine["machine"] = "m2"
        expect("another machine moves an E lane and not a D lane",
               d(cls[1], "G") == before_m and record(root, cls[1], "W", env_reader=reader)["env"]["machine"]["machine"] == "m2")
        machine["machine"] = "m1"

        text = explain(root, dep[0], dep[1], "C", env_reader=reader)
        expect("explain names the input that moved", "crates/core/src/lib.rs" in text and text.startswith("C: selected"), text)
        text = explain(root, outside[0], outside[1], "C", env_reader=reader)
        expect("explain says when a lane is not selected", text.startswith("C: not selected"), text)
        sel = select(root, data[0], data[1], env_reader=reader, tables=tables)
        expect("select is digest inequality", sel == ["G", "O", "P"], sel)

        # A base with no declaration at all, and a head that adds it and moves one source.
        bare = step({lane_decl.DECL_PATH: None})
        redeclared = step({lane_decl.DECL_PATH: _DECL_FIXTURE, "crates/core/src/inner.rs": "pub fn i() { 2; }\n"})
        try:
            lanes(root, redeclared[0], tables=tables)
        except DigestError:
            cases += 1
        else:
            raise AssertionError("lane_digest selftest: a tree with no declaration was planned on its own")
        # Red if the base stops being read with the head's entries: every lane would be selected.
        sel = select(root, redeclared[0], redeclared[1], env_reader=reader, tables=tables)
        expect("a base with no declaration selects only the lanes whose inputs differ",
               bare[1] == redeclared[0] and sel == ["C", "O", "W", "B", "P"], sel)
        expect("a lane the base does not declare is read with the head's entry",
               digest(root, redeclared[0], "G", env_reader=reader, decls_from=redeclared[1]) == d(redeclared[1], "G"))
        got_base = lanes(root, redeclared[0], tables=tables, decls_from=redeclared[1])
        expect("the base's lane set is read with the head's declaration",
               [u["id"] for u in got_base] == [u["id"] for u in lanes(root, redeclared[1], tables=tables)], got_base)
        text = explain(root, redeclared[0], redeclared[1], "G", env_reader=reader)
        expect("explain says the base was read with the head's entry",
               text.startswith("G: not selected") and "read with" in text, text)
        # Red if a base that declares the lane is read with the head's entry instead of its own.
        respec = step({lane_decl.DECL_PATH: _DECL_FIXTURE.replace(
            'class = "D"\ndecl = ["docs/notes/**"]', 'class = "E"\nreason = "r"\ndecl = ["docs/notes/**"]')})
        sel = select(root, respec[0], respec[1], env_reader=reader, tables=tables)
        expect("a lane whose entry differs between the base and the head is selected", sel == ["G", "O", "P"], sel)
        no_r = _DECL_FIXTURE.replace('\n[[lane]]\nid = "R"\nfn = "layer_r_graph"\nclass = "D"\n', "")
        partial = step({lane_decl.DECL_PATH: no_r})
        whole = step({lane_decl.DECL_PATH: _DECL_FIXTURE})
        sel = select(root, whole[0], whole[1], env_reader=reader, tables=tables)
        expect("a lane the base's declaration has no entry for is read with the head's",
               no_r != _DECL_FIXTURE and partial[1] == whole[0] and sel == ["O", "P"], sel)
        undeclared = step({RUNCI: _RUNCI_FIXTURE + "run_layer X layer_c_app || overall=1\n",
                           WORKFLOWS[0]: _CI_FIXTURE + "      - run: bash scripts/run-ci.sh --layer X\n"})
        try:
            lanes(root, undeclared[1], tables=tables)
        except DigestError:
            cases += 1
        else:
            raise AssertionError("lane_digest selftest: a lane with no declaration was planned")
        try:
            digest(root, undeclared[1], "X", env_reader=reader)
        except DigestError:
            cases += 1
        else:
            raise AssertionError("lane_digest selftest: a lane with no declaration was digested")
    calls = cargo_calls('cd crates && cargo test -p a --features x\necho "cargo test failed"\ncargo build --manifest-path "$ROOT/deploy/x/Cargo.toml"\n# cargo test -p commented\n')
    expect("cargo calls are read from executed lines", [(c.sub, c.packages, c.manifest, c.cwd) for c in calls]
           == [("test", ("a",), None, "crates"), ("build", (), "$ROOT/deploy/x/Cargo.toml", None)], calls)
    looped = cargo_calls('for crate in a "b"; do\n    (cd crates && cargo build -p "$crate")\ndone\n'
                         'read -r crate\ncargo build -p "${crate}"\n')
    # Red if a `for` over literal words is not expanded, or a `read` does not unbind it.
    expect("a for over literal words names each, and a read unbinds its variable",
           [(c.packages, bool(c.unresolved)) for c in looped] == [(("a", "b"), False), (("${crate}",), True)], looped)
    over = cargo_calls('for m in $list; do cargo test -p "$m"; done\n')
    expect("a for over anything else leaves its variable unread", len(over) == 1 and bool(over[0].unresolved), over)
    plain = cargo_calls('BIN=wz-a\nbuild() {\n    cargo build -p "$BIN"\n}\nR=a\nR="b"\ncargo test -p "${R}"\n'
                        'P=a\nread -r P\ncargo build -p "$P"\nQ=a\nQ="$1"\ncargo build -p "$Q"\n'
                        'S=a\necho "${S:=b}"\ncargo build -p "$S"\n')
    # Red if a variable bound only to literal words is not read as those words, or one bound any
    # other way (a read, a computed value, a default assigned in an expansion) is.
    expect("a variable a text binds only to literal words names each, and no other is read",
           [(c.packages, bool(c.unresolved)) for c in plain]
           == [(("wz-a",), False), (("a", "b"), False), (("$P",), True), (("$Q",), True), (("$S",), True)], plain)
    refs = python_refs('import subprocess\nsubprocess.run(["cargo", "metadata", "--no-deps"])\n'
                       'subprocess.run(["cargo", f"+{tc}", "rustdoc", "-p", name])\nsubprocess.run(["cargo"] + rest)\n')
    # Red if `_cargo_argv` misreads the subcommand past a toolchain word, or calls a list with a
    # computed word constant.
    expect("an argv list says its cargo subcommand, and its words when all are constants",
           refs is not None and set(refs.cargo) == {("metadata", ("metadata", "--no-deps")), ("rustdoc", None), ("?", ())},
           refs and refs.cargo)
    named = python_refs('import subprocess\nPKG = "core"\nsubprocess.run(["cargo", "build", "-p", PKG])\n')
    # Red if a name the module binds once to a string stops being the word it spells.
    expect("a module's string constant is a constant word of an argv list",
           named is not None and named.cargo == [("build", ("build", "-p", "core"))], named and named.cargo)
    for rebound in ('def f(PKG):\n    subprocess.run(["cargo", "build", "-p", PKG])\n',
                    'for PKG in names:\n    subprocess.run(["cargo", "build", "-p", PKG])\n',
                    'subprocess.run(["cargo", "build", "-p", PKG])\nglobals()["PKG"] = other\n'):
        got_refs = python_refs('import subprocess\nPKG = "core"\n' + rebound)
        # Red if a name bound a second time, or one a computed name can reach, is read as constant.
        expect(f"a name bound again is no constant ({rebound.split(chr(10))[0]!r})",
               got_refs is not None and got_refs.cargo == [("build", None)], got_refs and got_refs.cargo)
    helper = FIXTURE["scripts/lib/helper.py"]
    lib = python_refs(helper, None, frozenset())
    full = python_refs(helper)
    # Red if an import reads a module whole, or reads a definition its importers do not name.
    expect("a module imported for none of its definitions runs only its top level",
           lib is not None and lib.cargo == [] and full is not None and full.cargo == [("build", None)], lib)
    expect("a definition an importer names is read", python_refs(helper, None, frozenset({"build"})).cargo == [("build", None)])
    gated = ('import os\n\nX = 1\n\n\ndef selftest():\n    import costly\n    return costly.CASES\n\n\n'
             'def main():\n    return selftest()\n\n\nif __name__ == "__main__":\n    main()\n')
    expect("the __main__ guard and what only it calls are not run by an import",
           python_refs(gated, None, frozenset()).imports == ["os"]
           and python_refs(gated, None, frozenset({"main"})).uses.get("costly") == frozenset({"CASES"}))
    for shape in ('\n@register\ndef hidden():\n    return build()\n',
                  '\ndef table():\n    return globals()["build"]()\n',
                  '\ndef table():\n    subprocess.run([sys.executable, __file__, "--x"])\n',
                  '\ndef __getattr__(name):\n    return build\n'):
        reach = python_refs(helper + shape, None, frozenset({"table"}))
        # Red if a definition a decorator keeps, a name computed at run time, a module that runs
        # itself or one that answers any name is narrowed: the build would leave the key.
        expect(f"a module that can reach a definition by no name its code spells is read whole ({shape.split(chr(10))[1]!r})",
               reach is not None and ("build", None) in reach.cargo, reach and reach.cargo)
    importer = python_refs('import helper\nimport other as o\nimport pkg.sub\nfrom gate import a, b\nfrom star import *\n'
                           'helper.X\nhelper.build()\nkeep(o)\n')
    # Red if a module's uses stop being its attributes, or a use that cannot be read is narrowed.
    expect("an importer uses what it reads off a module, and every name of one it passes",
           importer is not None and importer.uses == {"helper": frozenset({"X", "build"}), "other": None, "pkg": None,
                                                      "gate": frozenset({"a", "b"}), "star": None}, importer and importer.uses)

    shell = parse_shell('#!/usr/bin/env bash\nf() {\n    cat <<EOF\n}\nEOF\n    echo "}" \'{\' ${x:-}}  # }\n}\n'
                        'g() { echo one; }\n# h() {\nh ()\n{\n    case "$1" in\n    a) echo "$(echo ")")" ;;\n    esac\n}\n'
                        'function k {\n    arr=(a # )\n    b)\n}\nrun_layer X layer_x || overall=1\nf\n')
    # Red if a heredoc's `}`, a quoted brace, a case pattern's `)` or a comment moves a boundary.
    expect("the reader finds each top-level function whole",
           sorted(shell.funcs) == ["f", "g", "h", "k"] and shell.funcs["g"] == "g() { echo one; }"
           and shell.funcs["f"] == 'f() {\n    cat <<EOF\n}\nEOF\n    echo "}" \'{\' ${x:-}}\n}', shell)
    expect("the code outside the functions keeps no comment and no dispatch line", shell.top.strip() == "f", shell.top)
    for bad, says in (('f() {\n    cat <<EOF\n    no end\n}\n', "heredoc"), ('f() {\n    echo "open\n}\n', 'a " is not closed'),
                      ('f() {\n    :\n', "a { is not closed"), ('f() (\n    :\n)\n', "is not a { } group"),
                      ('f() {\n    if true; then :; done\n}\n', "done closes no do")):
        try:
            parse_shell(bad)
        except ShellParseError as err:
            # Red if the reader stops refusing a text it cannot split, or stops saying why.
            expect(f"a text the reader cannot split is refused ({says})", says in str(err), err)
        else:
            raise AssertionError(f"lane_digest selftest: {bad!r} was split")

    opts = py_options(_READER_FIXTURE)
    expect("a script's store_true and one-value options are read",
           opts is not None and opts.flags == {"--read": "read", "--audit": "audit"} and opts.valued == {"--lane"}, opts)
    where = "scripts/lib/reader.py"
    # Red if a call site's words stop deciding the modes, or a site that may pass more is narrowed.
    for site, want in (('python3 scripts/lib/reader.py --read --lane "$1"\n', frozenset({"read"})),
                       ('out="$(python3 -I "$ROOT/scripts/lib/reader.py" --aud 2>&1)"\n', frozenset({"audit"})),
                       ('scripts/lib/reader.py --lane x\n', frozenset()),
                       ('python3 scripts/lib/reader.py "$@"\n', None),
                       ('s=scripts/lib/reader.py\npython3 "$s" --audit\n', None),
                       ('python3 scripts/lib/reader.py -ra\n', None),
                       ('echo nothing runs it\n', None)):
        got_modes = call_modes(site, where, opts)
        expect(f"the modes of {site.strip()!r}", got_modes == want, got_modes)
    expect("a script whose options cannot be read runs in every mode", call_modes("python3 x.py --audit\n", "x.py", None) is None)
    runci_reads = [f for f, _ in python_refs(_READER_FIXTURE).found if f == RUNCI]
    narrowed = python_refs(_READER_FIXTURE, frozenset({"read"}))
    # Red if `_py_reached` enters the body of a flag no call site passes, or leaves out one it does.
    expect("a mode leaves out the branch only another flag enters",
           runci_reads == [RUNCI] and narrowed is not None and not any(f == RUNCI for f, _ in narrowed.found), narrowed)
    expect("the mode that passes the flag reaches it",
           any(f == RUNCI for f, _ in python_refs(_READER_FIXTURE, frozenset({"read", "audit"})).found))
    respawn = _READER_FIXTURE.replace("    return 0\n", '    subprocess.run([sys.executable, __file__, "--audit"])\n    return 0\n')
    expect("a script that runs itself with a flag reaches that flag's branch",
           respawn != _READER_FIXTURE and any(f == RUNCI for f, _ in python_refs(respawn, frozenset({"read"})).found))
    own_list = _READER_FIXTURE.replace("args = ap.parse_args()", "args = ap.parse_args(sys.argv[1:])")
    expect("a script that is given its arguments is read in every mode",
           own_list != _READER_FIXTURE and py_options(own_list) is None
           and any(f == RUNCI for f, _ in python_refs(own_list, frozenset({"read"})).found))
    print(f"lane_digest selftest: {cases} cases pass")
    return 0


def check(root: Path) -> int:
    """Every declared lane of HEAD has a digest, read with a fixed machine so the check asks the
    tree and not this host; prints how many lanes are opaque, each a debt of its entry."""
    def fixed(channel: str | None) -> dict[str, str]:
        return {"rustc": "check", "cargo": "check", "cc": "check", "python": "check", "machine": "check"}

    try:
        ctx = context(root, "HEAD")
    except DigestError as err:
        print(f"lane_digest: FAIL -- {err}", file=sys.stderr)
        return 1
    failed = 0
    opaque: list[str] = []
    for lane in ctx.dispatch:
        try:
            rec = record(root, "HEAD", lane, env_reader=fixed)
        except (DigestError, lane_graph.GraphError, KeyError) as err:
            print(f"lane_digest: FAIL -- lane {lane}: {err}", file=sys.stderr)
            failed += 1
            continue
        if rec["opaque"]:
            opaque.append(lane)
    if failed:
        return 1
    print(f"lane_digest: OK -- {len(ctx.dispatch)} lane(s) digested at HEAD; {len(opaque)} opaque "
          f"(always selected): {' '.join(opaque) or 'none'}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="RFC 0001 D(L, t): the digest a lane's verdict is keyed by")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--base")
    ap.add_argument("--head", default="HEAD")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--selftest", action="store_true")
    group.add_argument("--check", action="store_true")
    group.add_argument("--lanes", action="store_true")
    group.add_argument("--digest", metavar="ID")
    group.add_argument("--record", metavar="ID")
    group.add_argument("--explain", metavar="ID")
    group.add_argument("--select", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.check:
        return check(args.root)
    if (args.explain or args.select) and not args.base:
        ap.error("--explain and --select compare two trees: give --base")
    try:
        if args.lanes:
            for u in lanes(args.root, args.rev):
                print(json.dumps(u, sort_keys=True, separators=(",", ":")))
        elif args.digest:
            print(digest(args.root, args.rev, args.digest))
        elif args.record:
            print(json.dumps(record(args.root, args.rev, args.record), sort_keys=True, indent=1))
        elif args.explain:
            print(explain(args.root, args.base, args.head, args.explain))
        else:
            for lane_id in select(args.root, args.base, args.head):
                print(lane_id)
    except (DigestError, lane_graph.GraphError, GitError) as err:
        print(f"lane_digest: {err}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
