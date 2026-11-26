#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4654 (no register item) -- the cargo package graph of a tree, read from its manifests and lock
files, for the closure RFC 0001 keys a lane by.

RFC 0001 (`docs/rfc/0001-a-lane-lands-alone-and-a-verdict-is-keyed-by-what-it-read.md`,
sections 4.3 and 5.3) puts into a lane's key the files of every package its cargo calls build:
the package, everything reachable from it by normal and build edges, and its own dev-dependencies
with their closure, but not a dependency's dev-dependencies (cargo does not build those for a
dependent). This module computes that set for a commit's tree without a checkout, a network or a
build.

## Why the lock file and not `cargo metadata`

A digest is asked of trees that are not checked out (a base, a speculative candidate), and
`cargo metadata` needs a checkout and, for a resolve, the registry sources. A `Cargo.lock` is
cargo's own resolve written down: it holds every package of the workspace and its dependencies,
resolved over every feature and every target, so it is a SUPERSET of what any one call builds.
Reading it over-approximates a lane's closure (a selection costs more, a pass is never reused for
a change it could not see) and never under-approximates it. Feature-set precision, the one thing
`cargo tree -p <p> --features <f>` would add, is left to a later unit; nothing here re-implements
cargo's feature resolution.

The lock does not say an edge's kind. A local package's manifest does, and it is read
conservatively: an edge is dev-only only when the dependency is a key of a `dev-dependencies`
table and its name appears nowhere else in the manifest. A manifest shape this reader does not
follow therefore makes an edge normal (wider), never dev (narrower).

## Workspaces

Every tracked `Cargo.lock` beside a `Cargo.toml` is a workspace root: `crates/`, `xtask/`,
`oracles/`, each image under `deploy/`, ... A lock package without a `source` is local: its
directory is the tracked manifest of that name the workspace's members, its path dependencies or its
`[patch]` reach; one that lives in a submodule (`vendor/sce/...`) is that submodule's gitlink.

## Interface

    workspaces(tree) -> dict[str, Workspace]       keyed by root directory ("crates", ...)
    Workspace.packages {key: Package}, .members [key], .find(name) -> [key]
    closure(ws, keys) -> set[key]                  RFC 0001 4.3: normal and build transitive,
                                                   the roots' own dev edges one step
    reverse_closure(ws, keys) -> set[key]          RFC 0001 5.3: the packages a change reaches
    owners(spaces, path) -> [(ws_root, key)]       the local packages a tracked path belongs to
    inputs(tree, ws, keys) -> (paths, gitlinks, lock_entries)
                                                   what the closure of `keys` reads: every tracked
                                                   file of its local packages, the submodule pins
                                                   of those in submodules, the lock entry of each
                                                   package, and the workspace's own files
                                                   (`workspace_files`)
    resolve(spaces, spec) -> [(ws_root, key)]      a `lanes.toml` package spec or a cargo `-p`

  python3 scripts/lib/lane_graph.py --selftest
  python3 scripts/lib/lane_graph.py --check      the both-ways check on this tree (see `check`)
"""

from __future__ import annotations

import posixpath
import re
import sys
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from git_tree import Fixture, GitTree, glob_regex  # noqa: E402


class GraphError(ValueError):
    """The tree's manifests and locks cannot be read as a package graph; the message says where."""


class Package(NamedTuple):
    key: str
    name: str
    version: str
    source: str
    checksum: str
    #: the tracked directories of a local package (more than one only when two manifests of the
    #: name are both reached; the union is kept rather than a guess)
    dirs: tuple[str, ...]
    #: the submodule gitlinks a local package in a submodule lives in
    gitlinks: tuple[str, ...]
    member: bool


class Workspace(NamedTuple):
    root: str
    packages: dict[str, Package]
    #: key -> keys of every lock dependency
    edges: dict[str, frozenset[str]]
    #: key -> keys of the edges that are dev-only (members only)
    dev_only: dict[str, frozenset[str]]
    members: tuple[str, ...]
    #: the manifests every cargo call of this workspace loads
    manifests: tuple[str, ...]

    def find(self, name: str) -> list[str]:
        return sorted(k for k, p in self.packages.items() if p.name == name)


# -- the lock file -------------------------------------------------------------------------------

_LOCK_FIELD = re.compile(r'^(name|version|source|checksum)\s*=\s*"([^"]*)"$')


def parse_lock(text: str, where: str) -> list[dict]:
    """The `[[package]]` tables of a Cargo.lock (versions 1 to 4) as dicts with `dependencies`."""
    out: list[dict] = []
    cur: dict | None = None
    in_deps = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if in_deps:
            if line == "]":
                in_deps = False
                continue
            m = re.fullmatch(r'"([^"]+)",?', line)
            if m is None:
                raise GraphError(f"{where}:{number}: not a dependency line: {line!r}")
            assert cur is not None
            cur["dependencies"].append(m.group(1))
            continue
        if not line or line.startswith("#"):
            continue
        if line == "[[package]]":
            cur = {"dependencies": []}
            out.append(cur)
            continue
        if line.startswith("["):
            cur = None
            continue
        if cur is None:
            continue
        if line == "dependencies = [":
            in_deps = True
            continue
        inline = re.fullmatch(r"dependencies\s*=\s*\[(.*)\]", line)
        if inline:
            cur["dependencies"].extend(re.findall(r'"([^"]+)"', inline.group(1)))
            continue
        m = _LOCK_FIELD.match(line)
        if m:
            cur[m.group(1)] = m.group(2)
    for p in out:
        if "name" not in p or "version" not in p:
            raise GraphError(f"{where}: a [[package]] without a name and a version: {p}")
    return out


def _key(p: dict) -> str:
    return f"{p['name']} {p['version']} {p.get('source', '')}".rstrip()


def _dep_target(dep: str, by_name: dict[str, list[dict]], where: str) -> dict:
    """The lock package a dependency string ("name", "name ver", "name ver (source)") names."""
    m = re.fullmatch(r"(\S+)(?: (\S+))?(?: \((.+)\))?", dep)
    if m is None:
        raise GraphError(f"{where}: dependency {dep!r} is not `name [version [(source)]]`")
    name, version, source = m.groups()
    cands = [p for p in by_name.get(name, []) if version is None or p["version"] == version]
    if source is not None:
        cands = [p for p in cands if p.get("source", "") == source]
    if len(cands) != 1:
        raise GraphError(f"{where}: dependency {dep!r} names {len(cands)} package(s) of the lock")
    return cands[0]


# -- manifests -----------------------------------------------------------------------------------

_SECTION = re.compile(r"^\s*\[([^\[\]]+)\]\s*(?:#.*)?$")
_ARRAY_SECTION = re.compile(r"^\s*\[\[([^\[\]]+)\]\]\s*(?:#.*)?$")


def _sections(text: str) -> list[tuple[str, str]]:
    """(header, body) of every table of a manifest; the text before the first header is ("", ...)."""
    out: list[tuple[str, list[str]]] = [("", [])]
    for line in text.splitlines():
        array = _ARRAY_SECTION.match(line)
        m = _SECTION.match(line)
        if array:
            # `[[bin]]`, `[[test]]`: a table of its own, never a dependency table.
            out.append((f"[{array.group(1).strip()}]", []))
        elif m:
            out.append((m.group(1).strip(), []))
        else:
            out[-1][1].append(line)
    return [(h, "\n".join(b)) for h, b in out]


def package_name(text: str) -> str | None:
    """The `name` of a manifest's `[package]` table, or None for a virtual manifest."""
    for header, body in _sections(text):
        if header == "package":
            m = re.search(r'(?m)^\s*name\s*=\s*"([^"]+)"', body)
            return m.group(1) if m else None
    return None


def _dep_kind(header: str) -> tuple[str, str | None] | None:
    """("normal" | "dev" | "build", key-or-None) for a dependency table header, else None.
    `[dependencies.foo]` names its one key; `[target.'cfg(x)'.dev-dependencies]` is dev."""
    m = re.fullmatch(r"(?:target\.(?:'[^']*'|\"[^\"]*\"|[^.]+)\.)?(dependencies|dev-dependencies|build-dependencies)(?:\.([A-Za-z0-9_-]+))?", header)
    if m is None:
        return None
    kind = {"dependencies": "normal", "dev-dependencies": "dev", "build-dependencies": "build"}[m.group(1)]
    return kind, m.group(2)


def _token(name: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(name)}(?![A-Za-z0-9_-])")


def dev_only_names(text: str) -> set[str]:
    """The dependency names of a manifest that are dev-only, read conservatively (see the module
    docstring): a key of a dev table, whose name and whose `package = ...` name appear in no
    other table of the manifest."""
    dev: dict[str, str] = {}
    other_text: list[str] = []
    for header, body in _sections(text):
        kind = _dep_kind(header)
        if kind is None or kind[0] != "dev":
            other_text.append(header + "\n" + body)
            continue
        if kind[1] is not None:
            m = re.search(r'(?m)^\s*package\s*=\s*"([^"]+)"', body)
            dev[kind[1]] = m.group(1) if m else kind[1]
            continue
        for line in body.splitlines():
            m = re.match(r'^\s*([A-Za-z0-9_-]+)(?:\.workspace)?\s*=', line)
            if m is None:
                continue
            renamed = re.search(r'\bpackage\s*=\s*"([^"]+)"', line)
            dev[m.group(1)] = renamed.group(1) if renamed else m.group(1)
    rest = "\n".join(other_text)
    return {real for key, real in dev.items() if not _token(key).search(rest) and not _token(real).search(rest)}


def _path_refs(text: str, manifest_dir: str) -> set[str]:
    out: set[str] = set()
    for rel in re.findall(r'\bpath\s*=\s*"([^"]+)"', text):
        out.add(posixpath.normpath(posixpath.join(manifest_dir, rel)) if manifest_dir else posixpath.normpath(rel))
    return out


def _members(text: str, root: str, manifest_dirs: set[str]) -> set[str]:
    """The member directories `[workspace] members` names (globs resolved against the manifests)."""
    for header, body in _sections(text):
        if header != "workspace":
            continue
        m = re.search(r"(?ms)^\s*members\s*=\s*\[(.*?)\]", body)
        if m is None:
            return set()
        names: list[str] = []
        for line in m.group(1).splitlines():
            line = line.split("#", 1)[0]
            names.extend(re.findall(r'"([^"]+)"', line))
        out: set[str] = set()
        for name in names:
            rx = glob_regex(posixpath.normpath(posixpath.join(root, name)) if root else name)
            out.update(d for d in manifest_dirs if rx.fullmatch(d))
        return out
    return set()


# -- the workspaces of a tree --------------------------------------------------------------------

_SPACES: dict[str, tuple[dict[str, Workspace], dict[str, str]]] = {}


def _dir_of(path: str) -> str:
    return posixpath.dirname(path)


def _under(path: str, directory: str) -> bool:
    return directory == "" or path == directory or path.startswith(directory + "/")


def workspaces(tree) -> dict[str, Workspace]:
    """Every workspace of `tree` (a GitTree or a WorkTree) that reads as a graph. One that does
    not is left out and named by `broken(tree)`: a lane that builds in it then resolves no
    package and is opaque (always selected), which is the safe reading; `check` fails on it."""
    return _read(tree)[0]


def broken(tree) -> dict[str, str]:
    """{workspace root: why its manifests and lock do not read as a graph}."""
    return _read(tree)[1]


def _read(tree) -> tuple[dict[str, Workspace], dict[str, str]]:
    cache_key = getattr(tree, "commit", None)
    if cache_key is not None and cache_key in _SPACES:
        return _SPACES[cache_key]
    manifests = {_dir_of(p): tree.text(p) or "" for p in tree.entries if posixpath.basename(p) == "Cargo.toml"}
    names = {d: package_name(t) for d, t in manifests.items()}
    gitlinks = tree.gitlinks()
    roots = sorted(_dir_of(p) for p in tree.entries
                   if posixpath.basename(p) == "Cargo.lock" and _dir_of(p) in manifests)
    out: dict[str, Workspace] = {}
    bad: dict[str, str] = {}
    for root in roots:
        try:
            out[root] = _workspace(tree, root, manifests, names, gitlinks)
        except GraphError as err:
            bad[root] = str(err)
    if cache_key is not None:
        _SPACES[cache_key] = (out, bad)
    return out, bad


def _workspace(tree, root: str, manifests: dict[str, str], names: dict[str, str | None],
               gitlinks: dict[str, str]) -> Workspace:
    lock_path = f"{root}/Cargo.lock" if root else "Cargo.lock"
    lock = parse_lock(tree.text(lock_path) or "", lock_path)
    # Other workspace roots below this one are not part of it.
    nested = [d for d in manifests if d != root and _under(d, root)
              and (f"{d}/Cargo.lock" in tree.entries)]

    def inside(d: str) -> bool:
        return _under(d, root) and not any(_under(d, n) for n in nested)

    member_dirs = _members(manifests[root], root, set(manifests)) | ({root} if names.get(root) else set())
    reached: set[str] = set(member_dirs)
    frontier = [d for d in manifests if inside(d)]
    seen: set[str] = set()
    while frontier:
        d = frontier.pop()
        if d in seen:
            continue
        seen.add(d)
        for ref in _path_refs(manifests.get(d, ""), d):
            reached.add(ref)
            if ref in manifests:
                frontier.append(ref)
    reached |= {d for d in manifests if inside(d)}
    submodules = sorted({g for g in gitlinks for ref in reached if _under(ref, g)})

    by_name: dict[str, list[dict]] = {}
    for p in lock:
        by_name.setdefault(p["name"], []).append(p)
    packages: dict[str, Package] = {}
    for p in lock:
        key = _key(p)
        if p.get("source"):
            packages[key] = Package(key, p["name"], p["version"], p["source"], p.get("checksum", ""), (), (), False)
            continue
        dirs = tuple(sorted(d for d in reached if names.get(d) == p["name"]))
        if dirs:
            member = any(inside(d) for d in dirs)
            packages[key] = Package(key, p["name"], p["version"], "", "", dirs, (), member)
        elif submodules:
            packages[key] = Package(key, p["name"], p["version"], "", "", (), tuple(submodules), False)
        else:
            raise GraphError(f"{lock_path}: local package {p['name']} has no manifest the workspace reaches")
    edges: dict[str, frozenset[str]] = {}
    dev_only: dict[str, frozenset[str]] = {}
    for p in lock:
        key = _key(p)
        targets = [_dep_target(d, by_name, f"{lock_path}: {p['name']}") for d in p["dependencies"]]
        edges[key] = frozenset(_key(t) for t in targets)
        pkg = packages[key]
        if pkg.member:
            dev_names = dev_only_names(manifests[pkg.dirs[0]])
            dev_only[key] = frozenset(_key(t) for t in targets if t["name"] in dev_names)
        else:
            dev_only[key] = frozenset()
    members = tuple(sorted(k for k, p in packages.items() if p.member))
    loaded = sorted({f"{d}/Cargo.toml" if d else "Cargo.toml" for k in members for d in packages[k].dirs}
                    | {f"{root}/Cargo.toml" if root else "Cargo.toml"})
    return Workspace(root, packages, edges, dev_only, members, tuple(loaded))


def closure(ws: Workspace, keys) -> set[str]:
    """RFC 0001 4.3: the roots, everything reachable by normal and build edges, and the roots' own
    dev-only edges one step (each with its own normal closure); a reached package's dev-only edges
    are not followed."""
    out: set[str] = set()
    stack: list[str] = []
    for k in keys:
        out.add(k)
        stack.extend(ws.edges[k])
    while stack:
        k = stack.pop()
        if k in out:
            continue
        out.add(k)
        stack.extend(ws.edges[k] - ws.dev_only[k])
    return out


def reverse_closure(ws: Workspace, keys) -> set[str]:
    """RFC 0001 5.3: the packages whose closure holds one of `keys`: normal and build dependents
    transitively, a dev dependent one step (its tests, not its dependents)."""
    normal_rev: dict[str, set[str]] = {}
    dev_rev: dict[str, set[str]] = {}
    for src, dsts in ws.edges.items():
        for dst in dsts:
            (dev_rev if dst in ws.dev_only[src] else normal_rev).setdefault(dst, set()).add(src)
    out: set[str] = set(keys)
    stack = list(keys)
    while stack:
        k = stack.pop()
        for dependent in normal_rev.get(k, ()):
            if dependent not in out:
                out.add(dependent)
                stack.append(dependent)
    for k in list(out):
        out.update(dev_rev.get(k, ()))
    return out


def workspace_files(tree, ws: Workspace) -> list[str]:
    """What every cargo call of the workspace reads besides packages: the manifest of the root and
    of every member (cargo loads the whole workspace, and one manifest it cannot read fails every
    call), the toolchain pin, and the cargo configuration of the root and of each directory above
    it."""
    out = set(p for p in ws.manifests if p in tree.entries)
    for name in ("rust-toolchain.toml", "rust-toolchain"):
        for base in {"", ws.root}:
            path = f"{base}/{name}" if base else name
            if path in tree.entries:
                out.add(path)
    parts = ws.root.split("/") if ws.root else []
    for i in range(len(parts) + 1):
        base = "/".join(parts[:i])
        out.update(tree.under(f"{base}/.cargo" if base else ".cargo"))
    return sorted(out)


def inputs(tree, ws: Workspace, keys) -> tuple[set[str], dict[str, str], list[str]]:
    """What the closure of `keys` reads (see the module docstring): (tracked paths, {gitlink:
    commit}, lock entries as `name version source checksum` lines)."""
    paths: set[str] = set(workspace_files(tree, ws))
    links: dict[str, str] = {}
    lock_entries: list[str] = []
    all_links = tree.gitlinks()
    for k in sorted(closure(ws, keys)):
        p = ws.packages[k]
        lock_entries.append(f"{p.name} {p.version} {p.source} {p.checksum}".rstrip())
        for d in p.dirs:
            for path in tree.under(d):
                if path in all_links:
                    links[path] = all_links[path]
                else:
                    paths.add(path)
        for g in p.gitlinks:
            links[g] = all_links[g]
    return paths, links, lock_entries


def owners(spaces: dict[str, Workspace], path: str) -> list[tuple[str, str]]:
    """The local packages a tracked path belongs to: the deepest package directory holding it, in
    every workspace that has that package; a path in a submodule belongs to the packages there."""
    out: list[tuple[str, str]] = []
    for root, ws in spaces.items():
        best: list[tuple[int, str]] = []
        for k, p in ws.packages.items():
            for d in p.dirs:
                if _under(path, d):
                    best.append((len(d), k))
            for g in p.gitlinks:
                if _under(path, g):
                    best.append((len(g), k))
        if best:
            depth = max(b[0] for b in best)
            out.extend((root, k) for n, k in best if n == depth)
    return sorted(set(out))


def resolve(spaces: dict[str, Workspace], spec: str) -> list[tuple[str, str]]:
    """The (workspace, key) pairs a package spec names: "<ws>:*" every member of <ws>, "<ws>:<name>"
    the local package of that name there, "<name>" the package where it is a member (in every such
    workspace), or else every workspace where it is local. Empty when nothing matches."""
    ws_name, name = (spec.split(":", 1) if ":" in spec else (None, spec))
    if ws_name is not None:
        ws = spaces.get(ws_name)
        if ws is None:
            return []
        if name == "*":
            return [(ws_name, k) for k in ws.members]
        return [(ws_name, k) for k in ws.find(name) if not ws.packages[k].source]
    local = [(r, k) for r, ws in spaces.items() for k in ws.find(name) if not ws.packages[k].source]
    members = [(r, k) for r, k in local if spaces[r].packages[k].member]
    return sorted(members or local)


# -- the selftest and the check ------------------------------------------------------------------

#: A small workspace in which every rule has a case. `app` depends on `core` and dev-depends on
#: `support`; `core` depends on a registry crate and a crate in the submodule `vendor/sub`, and
#: dev-depends on `leaf`; `leaf` depends on another registry crate. `tool` is a second
#: workspace with its own lock that path-depends on `core`.
FIXTURE: dict[str, str] = {
    "crates/Cargo.toml": '[workspace]\nresolver = "2"\nmembers = [\n    # the members\n    "app", "core",\n    "leaf",\n    "support",\n]\n',
    "crates/app/Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\ncore = { path = "../core" }\n\n[dev-dependencies]\nsupport = { path = "../support" }\n',
    "crates/app/src/main.rs": "fn main() {}\n",
    "crates/core/Cargo.toml": '[package]\nname = "core"\nversion = "0.1.0"\n\n[dependencies]\nregdep = "1"\nsubcrate = { path = "../../vendor/sub/subcrate" }\n\n[target.\'cfg(unix)\'.dev-dependencies]\nleaf = { path = "../leaf" }\n',
    "crates/core/src/lib.rs": "pub fn f() {}\n",
    "crates/leaf/Cargo.toml": '[package]\nname = "leaf"\nversion = "0.1.0"\n\n[dependencies]\nother = "2"\n',
    "crates/leaf/src/lib.rs": "pub fn g() {}\n",
    "crates/support/Cargo.toml": '[package]\nname = "support"\nversion = "0.1.0"\n',
    "crates/support/src/lib.rs": "pub fn h() {}\n",
    "crates/Cargo.lock": (
        "version = 3\n\n"
        '[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = [\n "core",\n "support",\n]\n\n'
        '[[package]]\nname = "core"\nversion = "0.1.0"\ndependencies = [\n "leaf",\n "regdep",\n "subcrate",\n]\n\n'
        '[[package]]\nname = "leaf"\nversion = "0.1.0"\ndependencies = [\n "other",\n]\n\n'
        '[[package]]\nname = "other"\nversion = "2.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "aa"\n\n'
        '[[package]]\nname = "regdep"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "bb"\n\n'
        '[[package]]\nname = "subcrate"\nversion = "0.1.0"\n\n'
        '[[package]]\nname = "support"\nversion = "0.1.0"\n'
    ),
    "tool/Cargo.toml": '[package]\nname = "tool"\nversion = "0.1.0"\n\n[dependencies]\ncore = { path = "../crates/core" }\n',
    "tool/src/main.rs": "fn main() {}\n",
    "tool/Cargo.lock": (
        "version = 3\n\n"
        '[[package]]\nname = "core"\nversion = "0.1.0"\ndependencies = [\n "leaf",\n "regdep",\n "subcrate",\n]\n\n'
        '[[package]]\nname = "leaf"\nversion = "0.1.0"\ndependencies = [\n "other",\n]\n\n'
        '[[package]]\nname = "other"\nversion = "2.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "aa"\n\n'
        '[[package]]\nname = "regdep"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "bb"\n\n'
        '[[package]]\nname = "subcrate"\nversion = "0.1.0"\n\n'
        '[[package]]\nname = "tool"\nversion = "0.1.0"\ndependencies = [\n "core",\n]\n'
    ),
    "rust-toolchain.toml": '[toolchain]\nchannel = "1.0.0"\n',
    ".cargo/config.toml": "[build]\n",
    "README.md": "fixture\n",
}
FIXTURE_LINKS = {"vendor/sub": "1" * 40}


def selftest() -> int:
    cases = 0

    def expect(name: str, ok: bool, detail: object = "") -> None:
        nonlocal cases
        if not ok:
            raise AssertionError(f"lane_graph selftest: {name} FAILED {detail}")
        cases += 1

    with Fixture() as fx:
        rev = fx.commit(FIXTURE, FIXTURE_LINKS)
        tree = GitTree(fx.root, rev)
        spaces = workspaces(tree)
        expect("every lock beside a manifest is a workspace", sorted(spaces) == ["crates", "tool"], sorted(spaces))
        ws = spaces["crates"]
        names = lambda keys: sorted(ws.packages[k].name for k in keys)  # noqa: E731
        app = ws.find("app")
        # Red if the root's dev edge is dropped (`closure` stops adding the roots' edges whole).
        expect("a root's dev dependency is in its closure", "support" in names(closure(ws, app)), names(closure(ws, app)))
        # Red if `closure` follows a reached package's dev-only edges (`- ws.dev_only[k]`).
        expect("a dependency's dev dependency is not", "leaf" not in names(closure(ws, app)) and "other" not in names(closure(ws, app)), names(closure(ws, app)))
        expect("normal edges are transitive into the registry and a submodule",
               {"core", "regdep", "subcrate"} <= set(names(closure(ws, app))), names(closure(ws, app)))
        # Red if a target-specific dev table is read as normal (`_dep_kind`'s target prefix).
        expect("a target's dev table is dev", ws.dev_only[ws.find("core")[0]] == frozenset(ws.find("leaf")), ws.dev_only)
        expect("a registry package is no member", not ws.packages[ws.find("regdep")[0]].member)
        sub = ws.packages[ws.find("subcrate")[0]]
        expect("a package in a submodule is its gitlink", sub.gitlinks == ("vendor/sub",) and sub.dirs == (), sub)
        rev_core = names(reverse_closure(ws, ws.find("core")))
        expect("a change to core reaches app", rev_core == ["app", "core"], rev_core)
        # Red if dev dependents are followed transitively in `reverse_closure`.
        rev_support = names(reverse_closure(ws, ws.find("support")))
        expect("a dev dependent is reached one step", rev_support == ["app", "support"], rev_support)
        rev_leaf = names(reverse_closure(ws, ws.find("leaf")))
        expect("a dev edge does not carry a change past its dependent", rev_leaf == ["core", "leaf"], rev_leaf)
        expect("a leaf no one depends on stays alone", names(reverse_closure(ws, app)) == ["app"])
        paths, links, lock = inputs(tree, ws, app)
        expect("the closure's files are inputs", "crates/core/src/lib.rs" in paths and "crates/support/src/lib.rs" in paths, sorted(paths))
        expect("a file outside the closure is not", "crates/leaf/src/lib.rs" not in paths and "README.md" not in paths)
        expect("the workspace's own files are inputs", {"crates/Cargo.toml", "crates/leaf/Cargo.toml", "rust-toolchain.toml", ".cargo/config.toml"} <= paths)
        expect("the submodule pin is an input", links == {"vendor/sub": "1" * 40}, links)
        # Red if the lock is hashed whole instead of projected onto the closure.
        expect("the lock is projected onto the closure", any(e.startswith("regdep 1.0.0") for e in lock) and not any(e.startswith("other ") for e in lock), lock)
        expect("a path belongs to its package in each workspace", owners(spaces, "crates/core/src/lib.rs") == [("crates", ws.find("core")[0]), ("tool", spaces["tool"].find("core")[0])], owners(spaces, "crates/core/src/lib.rs"))
        expect("a package spec resolves where it is a member", resolve(spaces, "core") == [("crates", ws.find("core")[0])], resolve(spaces, "core"))
        expect("<ws>:* is every member", sorted(ws.packages[k].name for _, k in resolve(spaces, "crates:*")) == ["app", "core", "leaf", "support"])
        expect("no fixture workspace is broken", broken(tree) == {}, broken(tree))
        bad_rev = fx.commit({"tool/Cargo.lock": FIXTURE["tool/Cargo.lock"] + '\n[[package]]\nname = "ghost"\nversion = "0.1.0"\ndependencies = [\n "nowhere",\n]\n'})
        bad_tree = GitTree(fx.root, bad_rev)
        # Red if a workspace that does not read is dropped silently or fails the others.
        expect("a lock whose dependency names no package of it breaks its own workspace only",
               sorted(workspaces(bad_tree)) == ["crates"] and "tool" in broken(bad_tree), broken(bad_tree))
        expect("an unknown package resolves to nothing", resolve(spaces, "nope") == [] and resolve(spaces, "nows:app") == [])
    for text, what in (
        ('[[package]]\nname = "a"\nversion = "1"\ndependencies = [\n  bad\n]\n', "a dependency line that is no string"),
        ('[[package]]\nname = "a"\n', "a package without a version"),
    ):
        try:
            parse_lock(text, "fixture")
        except GraphError:
            cases += 1
        else:
            raise AssertionError(f"lane_graph selftest: {what} was read")
    by = {"a": [{"name": "a", "version": "1"}, {"name": "a", "version": "2"}]}
    try:
        _dep_target("a", by, "fixture")
    except GraphError:
        cases += 1
    else:
        raise AssertionError("lane_graph selftest: an ambiguous dependency was resolved")
    expect("a versioned dependency picks its version", _dep_target("a 2", by, "fixture")["version"] == "2")
    # The conservative kind reading: a name seen outside the dev table is normal.
    manifest = '[dependencies]\nx = { path = "x" }\n\n[dev-dependencies]\nx = { path = "x" }\ny = "1"\nz2 = { package = "zed", version = "1" }\n'
    expect("dev-only names are read conservatively", dev_only_names(manifest) == {"y", "zed"}, dev_only_names(manifest))
    # Red if an array table after a dev table is read as part of it (`_ARRAY_SECTION`).
    binned = manifest + '\n[[bin]]\nname = "tool"\n\n[dependencies.y]\nversion = "1"\n'
    expect("an array table ends a dev table, and a table-form dependency is normal", dev_only_names(binned) == {"zed"}, dev_only_names(binned))
    print(f"lane_graph selftest: {cases} cases pass")
    return 0


def check(root: Path) -> int:
    """This tree's graph, both ways, the way Layer C0d holds the doc-link expansion: a real edge
    widens (a change to `wz-session-core` reaches `wz-runtime-tokio`) and a leaf stays alone
    (nothing depends on `wz-ap-demo`). A reader that returned its input, or the workspace, fails
    one of the two."""
    tree = GitTree(root, "HEAD")
    spaces = workspaces(tree)
    for where, why in sorted(broken(tree).items()):
        print(f"lane_graph: FAIL -- workspace {where} does not read as a package graph: {why}", file=sys.stderr)
    if broken(tree):
        return 1
    ws = spaces.get("crates")
    if ws is None:
        print("lane_graph: FAIL -- no crates/ workspace with a Cargo.lock in this tree", file=sys.stderr)
        return 1
    session = ws.find("wz-session-core")
    demo = ws.find("wz-ap-demo")
    if not session or not demo:
        print("lane_graph: FAIL -- wz-session-core or wz-ap-demo is not a package of crates/", file=sys.stderr)
        return 1
    widened = {ws.packages[k].name for k in reverse_closure(ws, session)}
    alone = {ws.packages[k].name for k in reverse_closure(ws, demo)}
    bad = []
    if "wz-runtime-tokio" not in widened:
        bad.append("a change to wz-session-core does not reach wz-runtime-tokio")
    if alone != {"wz-ap-demo"}:
        bad.append(f"a change to wz-ap-demo reaches {sorted(alone - {'wz-ap-demo'})}")
    for b in bad:
        print(f"lane_graph: FAIL -- {b}", file=sys.stderr)
    if bad:
        return 1
    total = sum(len(w.packages) for w in spaces.values())
    print(f"lane_graph: OK -- {len(spaces)} workspace(s), {total} package(s); wz-session-core reaches "
          f"{len(widened)} package(s) including wz-runtime-tokio, wz-ap-demo reaches itself alone")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["--check"]:
        return check(Path(__file__).resolve().parents[2])
    print("usage: lane_graph.py --selftest | --check", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
