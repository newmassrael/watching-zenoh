#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4654 (no register item) -- D(L, t): the digest a lane's verdict is keyed by (RFC 0001, stage M1).

## Interface (fixed: the receipt store and the lane-gate step of `scripts/land.sh`, stages M2 and M3,
## call these names with these signatures; a change of meaning is a new SCHEMA word)

    lanes(root, rev, *, tables=None) -> list[dict]
        G(t) for the tree of `rev`: one dict per unit `bx --checks ci` runs, in the dispatch table's
        order: {"id": the unit's name ("C1nh", "Qzk:<part>"), "lane": the dispatch id, "part": the
        part or None, "class": "D" | "E" | "S", "opaque": bool, "unit": the planner's unit dict,
        whose "name" equals "id"}. `tables` overrides the planner's lane tables (a selftest's).
    digest(root, rev, lane_id, *, env_reader=None) -> str
        D(L, t) as 64 lowercase hex digits. `lane_id` is a dispatch id or `<id>:<part>`.
    record(root, rev, lane_id, *, env_reader=None) -> dict
        what the digest hashes, so an auditor recomputes it from the record alone with
        `digest_of(record)`: {"schema", "lane", "opaque", "spec", "env", "inputs"}.
    digest_of(record) -> str
    explain(root, base, head, lane_id, *, env_reader=None) -> str
        why the lane is or is not selected between two trees: equal digests, or the spec fields,
        env fields and input entries that differ.
    select(root, base, head, *, env_reader=None, tables=None) -> list[str]
        Sel (RFC 0001 5.1, the base form): the unit ids of G(head) whose digest at head differs
        from their digest at base, or that base does not have.
    DigestError       raised for a tree whose digest cannot be computed (no dispatch table, an
                      undeclared lane, a workflow that does not parse); never a silent default.

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

    D(L, t) = SHA-256( len-prefixed "wz-lane-digest/1", spec, env, inputs ), each a canonical JSON
    document (sorted keys, no whitespace), each prefixed by its length in bytes.

* **spec** -- the question: the lane id, part and function; its `lanes.toml` entry; the planner's
  unit and the env and provisioning the hosted job gives it; the text the lane runs from
  `scripts/run-ci.sh` (the script outside its functions, without the other lanes' dispatch
  lines, and every function the lane's function and that text name, transitively); and the blob
  of every script those name, transitively (`scripts/...` paths, a sibling a script names, a
  python module it imports).
* **env** -- what the verdict depends on outside the tree: the toolchain pin's blob, the
  `[tools.*]` tables of `bx.toml`, the oracle pins (`scripts/zenoh-c-oracle.pin`, the
  `UPSTREAM_VERSION` line of `scripts/lib/upstream_feature_census.py`), and what `env_reader`
  reads from the machine: `rustc -vV` and `cargo -V` of the pinned channel, `cc --version`,
  `python3 --version`, and for an E lane alone the machine's identity (a hash of
  `/etc/machine-id`, never the value).
* **inputs** -- M(L, t): (path, mode, blob) of every tracked file in inputs(L, t), (path, commit)
  of every submodule gitlink in it, and the lock entries of the packages it builds.
  inputs(L, t) is the union of: the cargo closure (`lane_graph.py`) of every package the lane's
  cargo calls name (`-p`, `--manifest-path`, `--workspace` after a `cd` to a workspace) and of
  its declared `packages` and `legs`; every tracked file and directory its executed lines name;
  and its declared `decl` globs.

The time, the machine (for D and S lanes), the commit id and the branch are not in the key.

## Opaque lanes (RFC 0001 5.4)

A lane is opaque when its inputs cannot be read off its commands: a cargo call whose package set is
computed (`-p "$pkg"`) or depends on a directory the reader cannot see, a script that spawns cargo
itself, or a lane that runs another lane (`run-ci.sh --layer`); unless its entry declares the
`packages` or `legs` it builds. An opaque lane's inputs are the WHOLE tree, so its digest is still
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
import contextlib
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
from git_tree import Fixture, GitTree, git  # noqa: E402

SCHEMA = "wz-lane-digest/1"
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

_FUNC = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) \{\n(.*?)^\}\n?", re.M | re.S)
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def split_runci(text: str) -> tuple[dict[str, str], str]:
    """({function: body}, the script outside its functions and without its dispatch lines)."""
    funcs = {m.group(1): m.group(2) for m in _FUNC.finditer(text)}
    rest = runci_plan.DISPATCH.sub("", _FUNC.sub("", text))
    return funcs, rest


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
    """What a text names: scripts it runs or imports, data files it reads, directories, gitlinks."""

    scripts: set[str]
    files: set[str]
    dirs: set[str]
    links: set[str]


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
    #: an argv list that starts with "cargo"
    spawns_cargo: bool
    #: an argv list naming run-ci.sh and --layer
    runs_lane: bool


def python_refs(text: str) -> PyRefs | None:
    """What a python text names, read by its syntax: a docstring, a bare string statement and a
    comment are no reference. None when the text does not parse."""
    try:
        module = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    lines = text.splitlines()
    bare: set[int] = set()
    consumed: set[int] = set()
    imports: list[str] = []
    found: list[tuple[str, bool]] = []
    spawns_cargo = False
    runs_lane = False
    for node in ast.walk(module):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            bare.add(id(node.value))

    def runs(node: ast.AST) -> bool:
        n = getattr(node, "lineno", 0)
        return 0 < n <= len(lines) and bool(_PY_SPAWN.search(lines[n - 1]))

    for node in ast.walk(module):
        if isinstance(node, (ast.List, ast.Tuple)):
            words = [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            spawns_cargo = spawns_cargo or words[:1] == ["cargo"]
            runs_lane = runs_lane or (any(w.endswith("run-ci.sh") for w in words) and "--layer" in words)
        if isinstance(node, ast.Import):
            imports.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module and not node.level:
                imports.append(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            first = node.args[0] if node.args else None
            if name == "import_module" and isinstance(first, ast.Constant) and isinstance(first.value, str):
                imports.append(first.value.split(".")[0])
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and id(node) not in consumed:
            segs = _div_segments(node, consumed)
            if segs:
                found.append(("/".join(segs), runs(node)))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in bare:
            for tok in _PATH.findall(node.value):
                found.append((tok, runs(node)))
            for name in _SIBLING.findall(node.value):
                found.append((name, runs(node)))
    return PyRefs(imports, found, spawns_cargo, runs_lane)


def names_in(text: str, base: str, tree, dirs: set[str], kind: str) -> Named:
    """What a text names, relative to the root or to `base`, the directory of its file.

    `kind` "shell": every script it names runs (`bash x.sh`, `source x.sh`, `python3 x.py`) and every
    other file it names is read. "python": what it imports runs, and a script named on a line that
    starts a program; every other path in a string of its code is read (one in a docstring or a
    comment is not). "code": what it imports, and nothing it reads -- the planner, whose part in a
    unit is already the unit and the hosted env the spec holds."""
    scripts: set[str] = set()
    files: set[str] = set()
    found_dirs: set[str] = set()
    links: set[str] = set()
    gitlinks = tree.gitlinks()

    def take(candidate: str, runs: bool) -> None:
        # A path written under a variable (`$ROOT/scripts/x.sh`) is read as the token
        # `ROOT/scripts/x.sh`: every tail of two or more segments is tried too.
        parts = candidate.split("/")
        tails = {"/".join(parts[i:]) for i in range(max(1, len(parts) - 1))} | {candidate}
        options = {posixpath.normpath(t) for t in tails} | {posixpath.normpath(posixpath.join(base, candidate))}
        for path in options:
            if path.startswith("../") or path in (".", ".."):
                continue
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
        return Named(scripts, files, found_dirs, links)
    refs = python_refs(text)
    if refs is None:
        # Not python this reader can parse: read it as a shell text reads, which runs more.
        return names_in(text, base, tree, dirs, "shell")
    for mod in refs.imports:
        take(posixpath.join(base, mod + ".py"), True)
    if kind == "python":
        for candidate, runs in refs.found:
            take(candidate, runs)
    if kind == "code":
        files.clear()
        found_dirs.clear()
        links.clear()
    return Named(scripts, files, found_dirs, links)


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


def cargo_calls(text: str) -> list[Call]:
    """Every cargo call of an executed shell text (see `Call`). A call whose selector holds a
    variable is unresolved and says why; a call inside a quoted string is read only when it names
    its packages, since an `echo` mentions cargo far more often than a `bash -c` runs it. The directory
    is a `cd` earlier on the call's line, or else the last line that is a `cd` alone (one inside a
    subshell starts with its parenthesis and is not read), with the text's plain assignments
    substituted."""
    out: list[Call] = []
    assigned: dict[str, str] = {}
    last_cd: str | None = None
    for line in executed(text).splitlines():
        a = _ASSIGN.match(line)
        if a:
            assigned[a.group(1)] = _expand(a.group(3), assigned)
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
                    packages.append(value)
                elif tok.startswith("--package="):
                    value = tok.split("=", 1)[1]
                    packages.append(value)
                elif tok.startswith("-p") and len(tok) > 2 and not tok.startswith("--"):
                    value = tok[2:]
                    packages.append(value)
                elif tok == "--manifest-path" and i + 1 < len(toks):
                    manifest = _expand(toks[i + 1], assigned)
                    i += 1
                elif tok.startswith("--manifest-path="):
                    manifest = _expand(tok.split("=", 1)[1], assigned)
                elif tok in ("--workspace", "--all"):
                    whole = True
                if value is not None and ("$" in value or "`" in value or not value):
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
    funcs: dict[str, str]
    preamble: str
    dispatch: dict[str, str]
    decls: dict[str, lane_decl.LaneDecl]
    hosted: dict[str, runci_plan.Hosted]
    dirs: set[str]
    spaces: dict[str, lane_graph.Workspace]


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


def context(root: Path, rev: str) -> Ctx:
    """The tree of `rev` read once: its dispatch table, declaration, hosted jobs and workspaces."""
    commit = git(root, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").decode().strip()
    key = (str(Path(root).resolve()), commit)
    if key in _CTX:
        return _CTX[key]
    tree = GitTree(root, commit)
    text = tree.text(RUNCI)
    if text is None:
        raise DigestError(f"{RUNCI} is not in the tree of {rev}")
    funcs, preamble = split_runci(text)
    dispatch = {m.group(1): m.group(2) for m in runci_plan.DISPATCH.finditer(text)}
    entries, _findings = lane_decl.parse(tree.text(lane_decl.DECL_PATH) or "")
    dirs: set[str] = set()
    for path in tree.entries:
        parts = path.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    ctx = Ctx(tree, text, funcs, preamble, dispatch, {e.id: e for e in entries}, _hosted(tree), dirs,
              lane_graph.workspaces(tree))
    _CTX[key] = ctx
    return ctx


# -- one lane's analysis -------------------------------------------------------------------------


class Analysis(NamedTuple):
    functions: list[str]
    runci_sha: str
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
        tried = ([posixpath.normpath(posixpath.join(cwd, manifest))] if cwd else []) + [manifest, f"crates/{manifest}"]
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


_ANALYSIS: dict[tuple[str, str], Analysis] = {}


def analyse(ctx: Ctx, lane: str) -> Analysis:
    """What lane `lane` runs and reads at this tree (see the module docstring), once per tree."""
    key = (ctx.tree.commit, lane)
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
    seeds = {fn, "run_layer"} | set(_WORD.findall(executed(ctx.preamble)))
    functions = function_closure(ctx.funcs, seeds)
    run_text = ctx.preamble + f"run_layer {lane} {fn} || overall=1\n" + "".join(
        f"{n}() {{\n{ctx.funcs[n]}}}\n" for n in functions)
    tree = ctx.tree
    gitlinks = tree.gitlinks()
    opaque: list[str] = []
    unresolved: list[str] = []
    scripts: dict[str, str] = {}
    files: set[str] = set()
    links: dict[str, str] = {}
    named_dirs: set[str] = set()
    builds: dict[str, set[str]] = {}
    # (text, the directory of its file, its kind for `names_in`); the dispatch script is in
    # scripts/ and runs from the root, so a name in it is tried against both.
    queue: list[tuple[str, str, str]] = [(ctx.preamble, "scripts", "shell")] + [
        (ctx.funcs[n], "scripts", "shell") for n in functions]
    # Every unit runs through the planner; a tree without one (a selftest's) has nothing to add.
    for path in ([PLANNER] if PLANNER in tree.entries else []) + ([entry.legs] if entry.legs else []):
        if path not in tree.entries:
            opaque.append(f"{path} is named by the lane's entry and is not in the tree")
            continue
        scripts[path] = tree.entries[path].oid
        kind = "code" if path == PLANNER else ("python" if path.endswith(".py") else "shell")
        queue.append(((tree.text(path) or ""), posixpath.dirname(path), kind))
    while queue:
        text, base, kind = queue.pop()
        body = executed(text)
        if kind == "python":
            refs = python_refs(text)
            if refs is None or refs.spawns_cargo:
                unresolved.append("a python script it runs spawns cargo, or cannot be parsed to tell")
            if refs is not None and refs.runs_lane:
                unresolved.append("a python script it runs runs another lane of run-ci.sh")
        elif kind == "shell":
            if re.search(r"run-ci\.sh\s+--layer", body):
                unresolved.append("it runs another lane of run-ci.sh")
            if _SPAWNS_CARGO.search(body):
                unresolved.append("a text it runs spawns cargo from an argv list")
            for call in cargo_calls(text):
                got, call_links, why = _resolve_call(ctx, call)
                for root, key in got:
                    builds.setdefault(root, set()).add(key)
                for link in call_links:
                    links[link] = gitlinks[link]
                if why:
                    unresolved.append(why)
        named = names_in(text, base, tree, ctx.dirs, kind)
        for link in named.links:
            links[link] = gitlinks[link]
        named_dirs |= named.dirs
        files |= named.files
        for path in sorted(named.scripts):
            if path == RUNCI:
                # Run whole (another lane of it): the lane reads all of it.
                files.add(path)
                continue
            if path in scripts:
                continue
            data = tree.read(path) or b""
            scripts[path] = tree.entries[path].oid
            is_python = path.endswith(".py") or data.startswith(b"#!/usr/bin/env python")
            queue.append((data.decode("utf-8", "replace"), posixpath.dirname(path),
                          "code" if kind == "code" else ("python" if is_python else "shell")))
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
    # A declaration of what the lane builds stands for the calls this reader cannot read.
    if unresolved and not (entry.packages or entry.legs):
        opaque.extend(unresolved)
    lock: set[str] = set()
    for root, keys in sorted(builds.items()):
        paths, ws_links, entries = lane_graph.inputs(tree, ctx.spaces[root], keys)
        files |= paths
        links.update(ws_links)
        lock.update(f"{root}: {e}" for e in entries)
    return Analysis(functions, _sha(run_text), scripts, files, links, sorted(lock), sorted(set(opaque)))


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


def record(root: Path, rev: str, lane_id: str, *, env_reader: EnvReader | None = None) -> dict:
    ctx = context(root, rev)
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
        "runci": a.runci_sha,
        "functions": a.functions,
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


def digest(root: Path, rev: str, lane_id: str, *, env_reader: EnvReader | None = None) -> str:
    return digest_of(record(root, rev, lane_id, env_reader=env_reader))


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


def lanes(root: Path, rev: str, *, tables: dict | None = None) -> list[dict]:
    ctx = context(root, rev)
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
    if undeclared:
        raise DigestError(f"lane(s) with no readable entry in {lane_decl.DECL_PATH}: {', '.join(undeclared)}")
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


def explain(root: Path, base: str, head: str, lane_id: str, *, env_reader: EnvReader | None = None) -> str:
    after = record(root, head, lane_id, env_reader=env_reader)
    d_after = digest_of(after)
    try:
        before = record(root, base, lane_id, env_reader=env_reader)
    except DigestError as err:
        return f"{lane_id}: selected -- it has no digest at {base} ({err}); D at {head} is {d_after}"
    d_before = digest_of(before)
    if d_before == d_after:
        return f"{lane_id}: not selected -- D is {d_after} at both {base} and {head}"
    lines = [f"{lane_id}: selected -- D moves from {d_before} at {base} to {d_after} at {head}"]
    if after["opaque"]:
        lines.append(f"  opaque (its inputs are the whole tree): {'; '.join(after['opaque'])}")
    for part in ("spec", "env"):
        changed = sorted(k for k in set(before[part]) | set(after[part]) if before[part].get(k) != after[part].get(k))
        if changed:
            lines.append(f"  {part} differs in: {', '.join(changed)}")
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
            before = digest(root, base, u["id"], env_reader=env_reader)
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
}
layer_o_opaque() {
    local pkg="$1"
    (cd crates && cargo test -p "$pkg") || return 1
}
layer_w_workspace() {
    (cd crates && cargo test --workspace) || return 1
}
run_layer C layer_c_app || overall=1
run_layer G layer_g_gate || overall=1
run_layer O layer_o_opaque || overall=1
run_layer W layer_w_workspace || overall=1
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
"""

FIXTURE: dict[str, str] = {
    **lane_graph.FIXTURE,
    RUNCI: _RUNCI_FIXTURE,
    lane_decl.DECL_PATH: _DECL_FIXTURE,
    WORKFLOWS[0]: _CI_FIXTURE,
    "scripts/lib/gate.py": 'import helper\n\nTABLE = "deploy/table.json"\n',
    "scripts/lib/helper.py": "X = 1\n",
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
               == [("C", "D", "C"), ("G", "D", "G"), ("O", "D", "O"), ("W", "E", "W")], got)
        expect("only the lane whose package is a variable is opaque", [u["id"] for u in got if u["opaque"]] == ["O"], got)
        rec = record(root, first, "C", env_reader=reader)
        expect("a record recomputes its own digest", digest_of(rec) == d(first, "C"))
        expect("the digest is 64 hex digits", re.fullmatch(r"[0-9a-f]{64}", d(first, "C")) is not None)
        # Red if the D lane's key carries the machine (`_env` stops dropping it for D).
        expect("a D lane's key holds no machine identity", "machine" not in rec["env"]["machine"], rec["env"])
        expect("an E lane's key holds it", record(root, first, "W", env_reader=reader)["env"]["machine"].get("machine") == "m1")
        expect("the helper function the lane calls is in its spec", "_fixture_helper" in rec["spec"]["functions"], rec["spec"]["functions"])

        # Each change below is one commit; each assertion names what, if broken, turns it red.
        outside = step({"README.md": "changed\n", "docs/other.md": "changed\n"})
        # Red if `inputs` hashes the whole tree for a lane that is not opaque.
        expect("a file outside every input set moves no transparent lane",
               not moved(outside, "C") and not moved(outside, "G") and not moved(outside, "W"))
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
        body = step({RUNCI: _RUNCI_FIXTURE.replace("cargo test -p app)", "cargo test -p app --quiet)")})
        # Red if the spec holds run-ci.sh whole instead of the lane's own text.
        expect("a lane's own function moves it and no other lane", moved(body, "C") and not moved(body, "G"))
        helper = step({RUNCI: _RUNCI_FIXTURE.replace("cargo test -p app)", "cargo test -p app --quiet)").replace("echo helper", "echo helper2")})
        expect("a function the lane calls moves it", moved(helper, "C") and not moved(helper, "G"))
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
        expect("select is digest inequality", sel == ["G", "O"], sel)
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
    except (DigestError, lane_graph.GraphError) as err:
        print(f"lane_digest: {err}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
