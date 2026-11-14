#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R4488 (no register item) -- the offline build entry of the consumer bundles: what a build of
them reads when it has no network and no `.git`, and a build that proves it.

    offline_build.py --check              derive the entry from the crates graph and compare
    offline_build.py --build [--bundle ID]...
                                          build every bundle (or the named ones) in a sandbox that
                                          holds only what the entry declares
    offline_build.py --selftest

A consumer that builds wz as one hermetic action (no `.git`, no network, the pinned source, the
lockfile's crates vendored and a pinned toolchain as its inputs) reads `deploy/offline-build.json`
as that action's input list. The file is the entry; this script is what holds it to the tree. The
design is `docs/target-build-contract.md` section 5d.

## --check: the entry against the graph

For each bundle, `cargo tree -e normal,build` of its package and features, on the host, is its
closure. From the closures and `cargo metadata` it derives, and compares with the entry:

  * every crate with a build script in any closure, as the set of `build_scripts` keys: a crate that
    enters a closure with a build script is a finding until someone reads what that script runs and
    writes it down, and a key no closure has any more is a finding too;
  * each bundle's `system_tools`, as the linker and the tools of the build scripts in its closure;
  * the submodules a closure reaches, as `source.submodules`, with the URL `.gitmodules` gives;
  * the toolchain channel, as `rust-toolchain.toml` states it;
  * the lockfile holds no git source (`cargo.crates` says the crates are crates.io's);
  * every name of `output_variables` is read by a build script of a closure, the commit variable by
    the file that reads it, and no build script of a closure names a variable that hands in an input
    the entry says is not one (`not_inputs`).

It reads the graph and writes nothing. What a build script runs is read by a person once, when the
crate enters the set; the check makes sure that happens, `--build` makes sure it was read right.

## --build: the entry, measured

Each bundle is built by `cargo build --locked --offline --release` in a bwrap sandbox (user, net,
pid and ipc namespaces) that holds only what the entry declares:

  * the source: the files the repository tracks, and the declared submodules', copied out of the
    checkout into a staging directory (outside the checkout); no `.git` is copied, and the
    checkout itself is not visible in the sandbox (`$HOME` is an empty tmpfs, and the checkout is
    covered by one when it is elsewhere);
  * the crates: `cargo vendor --locked` of the staged lockfile, made outside the sandbox, which is
    the one step allowed the network; inside, a `CARGO_HOME` of the staging directory replaces
    crates.io with that directory, and no other registry cache is visible;
  * the toolchain the channel names (`rustup which`), bound read-only;
  * PATH: the toolchain, a directory holding the commands of the declared tools by the names a
    build script or a compiler driver runs them (`cc`, `as`, `ld`, `c++`, `ar`) and one holding
    `git`, `curl` and `wget` as stubs that record their call and fail. Nothing else is on PATH; the environment is cleared and set to these,
    `WZ_SOURCE_COMMIT` and `LIBCLANG_PATH` when the caller has one;
  * no network: the sandbox has its own empty network namespace.

A bundle passes when cargo exits 0, no stub was called, every declared product is in the target
directory, and, for a bundle whose closure holds the commit variable's reader, the reader's build
script handed rustc (`commit_input.rustc_env`, read from cargo's own `build-script-executed`
messages) the version a checkout build of the same tree composes, `v<version>-<git describe>`. The
expected version is asked of `git` in the checkout, outside the sandbox. The product is not
searched for the string: a bundle that never reads `zenoh::GIT_VERSION` (ap-demo) links it away.

The staging directory is `WZ_OFFLINE_BUILD_ROOT`, else the machine's cache directory
(`$XDG_CACHE_HOME`, else `~/.cache`) under `watching-zenoh/offline-build/<key of the checkout>`. It
persists, so a second run copies what changed and builds incrementally; a root inside the checkout is
refused, because the sandbox covers the checkout.

Exit 0 on success, 1 on a finding or a failed build, 2 on a usage error or a host that cannot hold
the sandbox.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DECL = ROOT / "deploy" / "offline-build.json"
TOOLCHAIN_FILE = ROOT / "rust-toolchain.toml"
GITMODULES = ROOT / ".gitmodules"

TOP_KEYS = ["schema", "about", "source", "commit_input", "toolchain", "cargo", "system_tools", "linker",
            "build_scripts", "output_variables", "bundles", "not_inputs"]
BUNDLE_KEYS = ["id", "package", "features", "default_features", "products", "system_tools"]
SUBMODULE_KEYS = ["path", "url", "commit"]
NOT_INPUT_KEYS = ["id", "why", "list", "hand_in"]
SCHEMA = 1

# The arguments the commit variable stands in for: `crates/wz-zenoh/build.rs` asks `git` the same.
DESCRIBE = ["describe", "--always", "--dirty=-modified", "--abbrev=40", "--exclude=*"]
# Programs a build that has no network and no history must never call.
STUBBED = ("git", "curl", "wget")
TOOL_KEYS = ["commands", "variable", "what"]
# Variables carried into the sandbox when the caller sets them: they locate a declared tool that is
# not a command.
CARRIED = ("LIBCLANG_PATH",)

STUB = """#!/bin/sh
printf '%s\\n' "$0 $*" >> "$OFFLINE_BUILD_CALLS"
exit 1
"""


class Finding(Exception):
    """The entry and the tree disagree, or a build failed: exit 1."""


class Unusable(Exception):
    """The host cannot hold the sandbox, or the call is malformed: exit 2."""


# ---------------------------------------------------------------------------------------------
# The entry's shape


def load(path: Path = DECL) -> dict:
    decl = json.loads(path.read_text(encoding="utf-8"))
    problems = shape_findings(decl)
    if problems:
        raise Finding(f"{path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}: "
                      + "; ".join(problems))
    return decl


def _strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) and v for v in value)


def shape_findings(decl: object) -> list[str]:
    """What is wrong with the entry's shape, before any of it is compared with the tree."""
    if not isinstance(decl, dict):
        return ["the entry is not an object"]
    out: list[str] = []
    if sorted(decl) != sorted(TOP_KEYS):
        out.append(f"top-level keys are {sorted(decl)}, expected {sorted(TOP_KEYS)}")
        return out
    if decl["schema"] != SCHEMA:
        out.append(f"schema is {decl['schema']!r}, this reader reads {SCHEMA}")
    subs = decl["source"].get("submodules") if isinstance(decl["source"], dict) else None
    if not isinstance(subs, list) or any(not isinstance(s, dict) or sorted(s) != sorted(SUBMODULE_KEYS)
                                         for s in subs):
        out.append(f"source.submodules is not a list of objects with {SUBMODULE_KEYS}")
    commit = decl["commit_input"]
    if not isinstance(commit, dict) or not all(isinstance(commit.get(k), str)
                                               for k in ("variable", "read_by", "rustc_env")):
        out.append("commit_input has no `variable`, `read_by` and `rustc_env`")
    if not isinstance(decl["toolchain"], dict) or not isinstance(decl["toolchain"].get("channel"), str):
        out.append("toolchain has no `channel`")
    cargo = decl["cargo"]
    if not isinstance(cargo, dict) or not all(isinstance(cargo.get(k), str) for k in ("manifest", "lockfile")) \
            or not _strings(cargo.get("flags")):
        out.append("cargo has no `manifest`, `lockfile` and `flags`")
    tools = decl["system_tools"]
    if not isinstance(tools, dict) or not tools:
        out.append("system_tools is not a non-empty object")
        tools = {}
    for name, tool in sorted(tools.items()):
        if not isinstance(tool, dict) or sorted(tool) != TOOL_KEYS:
            out.append(f"system tool {name!r} does not have exactly {TOOL_KEYS}")
        elif not (_strings(tool["commands"]) or tool["commands"] == []) \
                or tool["commands"] != sorted(set(tool["commands"])):
            out.append(f"system tool {name!r}: commands are not a sorted list of unique names")
    if decl["linker"] not in tools:
        out.append(f"the linker {decl['linker']!r} is not a declared system tool")
    scripts = decl["build_scripts"]
    if not isinstance(scripts, dict) or not all(_strings(v) or v == [] for v in scripts.values()):
        out.append("build_scripts is not an object of tool lists")
    else:
        for name, used in sorted(scripts.items()):
            for tool in used:
                if tool not in tools:
                    out.append(f"build script {name!r} names {tool!r}, which is not a declared system tool")
            if used != sorted(set(used)):
                out.append(f"build script {name!r}: its tools are not sorted and unique")
    if not isinstance(decl["output_variables"], dict) or not _strings(decl["output_variables"].get("names")):
        out.append("output_variables has no `names`")
    bundles = decl["bundles"]
    if not isinstance(bundles, list) or not bundles:
        out.append("bundles is not a non-empty list")
        bundles = []
    ids, packages = [], []
    for b in bundles:
        if not isinstance(b, dict) or sorted(b) != sorted(BUNDLE_KEYS):
            out.append(f"a bundle does not have exactly {BUNDLE_KEYS}")
            continue
        ids.append(b["id"])
        packages.append(b["package"])
        if not (_strings(b["features"]) or b["features"] == []) or b["features"] != sorted(set(b["features"])):
            out.append(f"bundle {b['id']!r}: features are not a sorted list of unique names")
        if not isinstance(b["default_features"], bool):
            out.append(f"bundle {b['id']!r}: default_features is not a boolean")
        if not _strings(b["products"]):
            out.append(f"bundle {b['id']!r}: products is not a non-empty list of names")
        for tool in b["system_tools"] if isinstance(b["system_tools"], list) else []:
            if tool not in tools:
                out.append(f"bundle {b['id']!r} names {tool!r}, which is not a declared system tool")
    for what, names in (("bundle id", ids), ("bundle package", packages)):
        twice = sorted({n for n in names if names.count(n) > 1})
        if twice:
            out.append(f"{what} declared twice: {', '.join(twice)}")
    nots = decl["not_inputs"]
    if not isinstance(nots, list) or any(not isinstance(n, dict) or sorted(n) != sorted(NOT_INPUT_KEYS)
                                         for n in nots):
        out.append(f"not_inputs is not a list of objects with {NOT_INPUT_KEYS}")
    return out


# ---------------------------------------------------------------------------------------------
# What the tree says


def run(argv: list[str], cwd: Path) -> str:
    try:
        done = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)
    except FileNotFoundError as e:
        raise Unusable(f"{argv[0]} is not on PATH ({e})") from e
    if done.returncode != 0:
        raise Finding(f"`{' '.join(argv)}` in {cwd} exited {done.returncode}:\n{done.stderr.strip()}")
    return done.stdout


def toolchain_channel(text: str) -> str:
    """The channel `rust-toolchain.toml` pins, from its `[toolchain]` table."""
    table = re.search(r"^\[toolchain\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    channel = re.search(r'^channel\s*=\s*"([^"]+)"\s*$', table.group(1), re.M) if table else None
    if not channel:
        raise Finding("rust-toolchain.toml states no [toolchain] channel")
    return channel.group(1)


def gitmodules(text: str) -> dict[str, str]:
    """Each submodule's path and URL, as `.gitmodules` states them."""
    out: dict[str, str] = {}
    for block in re.split(r"^\[submodule ", text, flags=re.M)[1:]:
        path = re.search(r"^\s*path\s*=\s*(\S+)\s*$", block, re.M)
        url = re.search(r"^\s*url\s*=\s*(\S+)\s*$", block, re.M)
        if path and url:
            out[path.group(1)] = url.group(1)
    return out


TREE_LINE = re.compile(r"^(\S+) v(\S+)")


def parse_tree(text: str) -> list[tuple[str, str]]:
    """The packages of a `cargo tree --prefix none -f '{p}'` listing, each once."""
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        m = TREE_LINE.match(line.strip())
        if m:
            seen.add((m.group(1), m.group(2)))
    return sorted(seen)


def tree_argv(bundle: dict) -> list[str]:
    argv = ["cargo", "tree", "--locked", "-e", "normal,build", "-p", bundle["package"],
            "--prefix", "none", "-f", "{p}"]
    if bundle["features"]:
        argv += ["--features", ",".join(bundle["features"])]
    if not bundle["default_features"]:
        argv.append("--no-default-features")
    return argv


@dataclass
class Package:
    """What `cargo metadata` says of one package that matters here."""

    dir: Path
    build_script: Path | None


def parse_metadata(doc: dict) -> dict[tuple[str, str], Package]:
    out: dict[tuple[str, str], Package] = {}
    for p in doc["packages"]:
        script = next((Path(t["src_path"]) for t in p["targets"] if "custom-build" in t["kind"]), None)
        out[(p["name"], p["version"])] = Package(Path(p["manifest_path"]).parent, script)
    return out


@dataclass
class Graph:
    """What the closures of the bundles hold, as `--check` compares it."""

    scripts: dict[str, list[str]] = field(default_factory=dict)   # bundle id -> build-script crates
    packages: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # bundle id -> closure
    submodules: list[str] = field(default_factory=list)          # submodule paths reached
    script_texts: dict[str, str] = field(default_factory=dict)   # crate -> its build script's text


def build_script_text(script: Path) -> str:
    """A build script and the modules beside it (`build/**.rs`), which is what it may run."""
    files = [script] + sorted(script.parent.glob("build/**/*.rs"))
    return "\n".join(f.read_text(encoding="utf-8", errors="replace") for f in files if f.is_file())


def derive(closures: dict[str, list[tuple[str, str]]], meta: dict[tuple[str, str], Package],
           submodule_paths: list[str], root: Path, read=build_script_text) -> Graph:
    graph = Graph()
    reached: set[str] = set()
    for bid, closure in closures.items():
        graph.packages[bid] = closure
        names: set[str] = set()
        for key in closure:
            pkg = meta.get(key)
            if pkg is None:
                raise Finding(f"`cargo metadata` has no {key[0]} v{key[1]}, which the closure of {bid} holds")
            if pkg.build_script is not None:
                names.add(key[0])
                if key[0] not in graph.script_texts:
                    graph.script_texts[key[0]] = read(pkg.build_script)
            try:
                rel = pkg.dir.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                continue
            for sub in submodule_paths:
                if rel == sub or rel.startswith(sub + "/"):
                    reached.add(sub)
        graph.scripts[bid] = sorted(names)
    graph.submodules = sorted(reached)
    return graph


def reads_variable(text: str, name: str) -> bool:
    """Whether a build script's text names the variable `name`: literally, or composed the way
    librocksdb-sys composes its library variables, a quoted stem handed to a `format!` whose text is
    `{..}_<rest>` (`try_to_find_and_link_lib("SNAPPY")` and `format!("{lib_name}_LIB_DIR")`)."""
    if name in text:
        return True
    for cut in (m.start() for m in re.finditer("_", name)):
        stem, rest = name[:cut], name[cut + 1:]
        if f'"{stem}"' in text and re.search(r"\{[A-Za-z_]*\}_" + re.escape(rest) + '"', text):
            return True
    return False


def findings(decl: dict, graph: Graph, channel: str, modules: dict[str, str], lockfile: str,
             read_file) -> list[str]:
    """Where the entry and the tree disagree. `read_file(rel)` is a tree file's text, or None."""
    out: list[str] = []
    if decl["toolchain"]["channel"] != channel:
        out.append(f"toolchain.channel is {decl['toolchain']['channel']!r}, rust-toolchain.toml pins {channel!r}")

    union = sorted({n for names in graph.scripts.values() for n in names})
    declared = sorted(decl["build_scripts"])
    for name in sorted(set(union) - set(declared)):
        holders = [bid for bid, names in graph.scripts.items() if name in names]
        out.append(f"crate {name!r} has a build script in the closure of {', '.join(holders)} and no "
                   f"`build_scripts` row: read what it runs and declare its tools ([] for none)")
    for name in sorted(set(declared) - set(union)):
        out.append(f"`build_scripts` declares {name!r}, which no bundle's closure builds a script for")

    for b in decl["bundles"]:
        names = graph.scripts.get(b["id"], [])
        want = sorted({decl["linker"]} | {t for n in names for t in decl["build_scripts"].get(n, [])})
        if b["system_tools"] != want:
            out.append(f"bundle {b['id']!r}: system_tools is {b['system_tools']}, its closure needs {want} "
                       f"(the linker and its build scripts' tools)")

    subs = decl["source"]["submodules"]
    declared_subs = sorted(s["path"] for s in subs)
    if declared_subs != graph.submodules:
        out.append(f"source.submodules is {declared_subs}, the closures reach {graph.submodules}")
    for s in subs:
        if s["path"] in modules and modules[s["path"]] != s["url"]:
            out.append(f"submodule {s['path']}: url is {s['url']!r}, .gitmodules says {modules[s['path']]!r}")
        elif s["path"] not in modules:
            out.append(f"submodule {s['path']} is not in .gitmodules")

    if re.search(r'^source = "git\+', lockfile, re.M):
        out.append("the lockfile holds a git source, which a build with no network and no vendored "
                   "directory for it cannot read; `cargo.crates` says it holds none")

    texts = graph.script_texts
    for name in decl["output_variables"]["names"]:
        if not any(reads_variable(t, name) for t in texts.values()):
            out.append(f"output_variables names {name}, which no build script of a closure reads")

    commit = decl["commit_input"]
    reader = read_file(commit["read_by"])
    if reader is None:
        out.append(f"commit_input.read_by {commit['read_by']} does not exist")
    else:
        for key in ("variable", "rustc_env"):
            if commit[key] not in reader:
                out.append(f"commit_input.read_by {commit['read_by']} does not name {commit[key]}")

    for item in decl["not_inputs"]:
        script = next((t for t in item["list"].split() if "/" in t), item["list"])
        text = read_file(script)
        if text is None:
            out.append(f"not_inputs {item['id']}: {script} does not exist")
            continue
        for var in item["hand_in"]:
            if var not in text:
                out.append(f"not_inputs {item['id']}: {script} does not take {var}")
            readers = sorted(n for n, t in texts.items() if var in t)
            if readers:
                out.append(f"not_inputs {item['id']}: the build script of {', '.join(readers)} reads {var}, "
                           f"so it is an input")
    return out


def tree_file(rel: str) -> str | None:
    path = ROOT / rel
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else None


def metadata(decl: dict) -> dict[tuple[str, str], Package]:
    """Every package of the workspace's graph. `--all-features`, because without it the document
    holds only what the workspace's default features reach, and a bundle's features reach more
    (`memoffset` was the first one missing). Only the packages' targets and directories are read
    here, never the resolve's edges, so the lock-level edges `cargo_activation.py` warns of do not
    enter: the closures are `cargo tree`'s."""
    crates = ROOT / Path(decl["cargo"]["manifest"]).parent
    return parse_metadata(json.loads(run(["cargo", "metadata", "--locked", "--all-features",
                                          "--format-version", "1"], crates)))


def measure(decl: dict) -> tuple[Graph, dict[tuple[str, str], Package]]:
    crates = ROOT / Path(decl["cargo"]["manifest"]).parent
    closures = {b["id"]: parse_tree(run(tree_argv(b), crates)) for b in decl["bundles"]}
    meta = metadata(decl)
    return derive(closures, meta, sorted(gitmodules(GITMODULES.read_text(encoding="utf-8"))), ROOT), meta


def check(decl: dict) -> tuple[Graph, dict[tuple[str, str], Package]]:
    graph, meta = measure(decl)
    found = findings(decl, graph, toolchain_channel(TOOLCHAIN_FILE.read_text(encoding="utf-8")),
                     gitmodules(GITMODULES.read_text(encoding="utf-8")),
                     (ROOT / decl["cargo"]["lockfile"]).read_text(encoding="utf-8"), tree_file)
    if found:
        raise Finding("deploy/offline-build.json disagrees with the tree:\n  " + "\n  ".join(found))
    return graph, meta


# ---------------------------------------------------------------------------------------------
# The build, in a sandbox that holds only the entry


def stage_root(env: dict[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    given = env.get("WZ_OFFLINE_BUILD_ROOT", "")
    if given:
        root = Path(given)
        if not root.is_absolute():
            raise Unusable(f"WZ_OFFLINE_BUILD_ROOT must be an absolute path, got {given!r}")
    else:
        cache = Path(env.get("XDG_CACHE_HOME") or Path.home() / ".cache")
        key = hashlib.sha256(str(ROOT).encode()).hexdigest()[:12]
        root = cache / "watching-zenoh" / "offline-build" / key
    # Both spellings: a `target` of the checkout may be a link to a machine cache, and a root under it
    # is still a path the checkout names.
    resolved = Path(os.path.realpath(root))
    for spelling in (Path(os.path.normpath(root)), resolved):
        if spelling.is_relative_to(ROOT) or spelling.is_relative_to(ROOT.resolve()):
            raise Unusable(f"the staging directory {spelling} is inside the checkout, which the sandbox covers")
    return resolved


def tracked(repo: Path, prefix: str = "") -> list[str]:
    """The files `repo` tracks (not its submodules' gitlinks), as paths under `prefix`."""
    out: list[str] = []
    listing = run(["git", "-C", str(repo), "ls-files", "-z", "--stage"], repo)
    for entry in listing.split("\0"):
        if not entry:
            continue
        meta, path = entry.split("\t", 1)
        if meta.split()[0] == "160000":
            continue
        out.append(f"{prefix}{path}")
    return out


def sync_tree(src: Path, rels: list[str], dest: Path) -> tuple[int, int]:
    """Make `dest` hold exactly the files `rels` of `src`: a file whose size and modification time
    already match is left alone (so cargo's fingerprints see no change), any other is copied with its
    times, and a file `dest` holds that is not in `rels` is removed. Returns (copied, removed)."""
    wanted = set()
    copied = removed = 0
    for rel in rels:
        s, d = src / rel, dest / rel
        if not os.path.lexists(s):
            continue  # removed from the working tree and not yet from the index: the tree has no such file
        wanted.add(rel)
        if s.is_symlink():
            target = os.readlink(s)
            if d.is_symlink() and os.readlink(d) == target:
                continue
            if os.path.lexists(d):
                d.unlink()
            d.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, d)
            copied += 1
            continue
        st = s.stat()
        if d.is_file() and not d.is_symlink():
            dt = d.stat()
            if dt.st_size == st.st_size and dt.st_mtime_ns == st.st_mtime_ns:
                continue
        if os.path.lexists(d):
            if d.is_dir() and not d.is_symlink():
                shutil.rmtree(d)
            else:
                d.unlink()
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(s, d, follow_symlinks=False)
        copied += 1
    if dest.is_dir():
        for dirpath, dirnames, filenames in os.walk(dest, topdown=False):
            for name in filenames + [n for n in dirnames if os.path.islink(os.path.join(dirpath, n))]:
                full = Path(dirpath) / name
                if full.relative_to(dest).as_posix() not in wanted:
                    full.unlink()
                    removed += 1
            for name in dirnames:
                full = Path(dirpath) / name
                if full.is_dir() and not full.is_symlink() and not any(full.iterdir()):
                    full.rmdir()
    return copied, removed


def stage_source(decl: dict, src: Path) -> None:
    rels = tracked(ROOT)
    for sub in decl["source"]["submodules"]:
        path = ROOT / sub["path"]
        if not (path / ".git").exists():
            raise Unusable(f"submodule {sub['path']} is not checked out: git submodule update --init {sub['path']}")
        rels += tracked(path, sub["path"] + "/")
    copied, removed = sync_tree(ROOT, rels, src)
    print(f"  offline-build: source staged at {src} ({len(rels)} files, {copied} copied, {removed} removed)")


def vendor(decl: dict, src: Path, stage: Path) -> Path:
    """The lockfile's crates, vendored once per lockfile digest. The one step with a network."""
    lock = (src / decl["cargo"]["lockfile"]).read_bytes()
    digest = hashlib.sha256(lock).hexdigest()
    out = stage / "vendor-crates"
    stamp = stage / "vendor-crates.sha256"
    if out.is_dir() and stamp.is_file() and stamp.read_text().strip() == digest:
        return out
    if out.exists():
        shutil.rmtree(out)
    stamp.unlink(missing_ok=True)
    crates = src / Path(decl["cargo"]["manifest"]).parent
    done = subprocess.run(["cargo", "vendor", "--locked", "--versioned-dirs", str(out)], cwd=crates,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, check=False)
    if done.returncode != 0:
        raise Finding(f"cargo vendor exited {done.returncode}:\n{done.stderr.strip()[-4000:]}")
    stamp.write_text(digest + "\n")
    print(f"  offline-build: crates vendored at {out}")
    return out


def toolchain_bin(channel: str) -> Path:
    rustc = Path(run(["rustup", "which", "--toolchain", channel, "rustc"], ROOT).strip())
    version = run([str(rustc), "-V"], ROOT)
    if not version.startswith(f"rustc {channel}"):
        raise Unusable(f"rustup's toolchain {channel} answers {version.strip()!r}")
    return Path(os.path.realpath(rustc)).parent


def tool_dir(decl: dict, stage: Path, bundles: list[dict]) -> Path:
    """The commands of the bundles' declared tools, by the names a build script or a compiler
    driver runs them. A tool's own command is the program its variable names when the caller sets
    it (`CC=clang`); every other command is the one on the caller's PATH."""
    out = stage / "tools"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for tool in sorted({t for b in bundles for t in b["system_tools"]}):
        spec = decl["system_tools"][tool]
        for command in spec["commands"]:
            named = (os.environ.get(spec["variable"]) if command == tool else None) or command
            found = shutil.which(named)
            if not found:
                raise Unusable(f"the declared tool {tool!r} ({spec['what']}) has no {command!r} on PATH "
                               f"(looked for {named!r})")
            os.symlink(os.path.realpath(found), out / command)
    return out


def stub_dir(stage: Path) -> Path:
    out = stage / "stubs"
    out.mkdir(parents=True, exist_ok=True)
    for name in STUBBED:
        path = out / name
        path.write_text(STUB)
        path.chmod(0o755)
    return out


def cargo_home(stage: Path, crates: Path) -> Path:
    home = stage / "cargo-home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.toml").write_text(
        "# Written by scripts/lib/offline_build.py: crates.io is the vendored directory, and nothing\n"
        "# else is reached.\n"
        "[source.crates-io]\n"
        'replace-with = "vendored-sources"\n\n'
        "[source.vendored-sources]\n"
        f'directory = "{crates}"\n\n'
        "[net]\n"
        "offline = true\n")
    return home


def sandbox_argv(stage: Path, toolchain: Path, path: list[Path], env: dict[str, str], cwd: Path,
                 home: Path | None = None, checkout: Path = ROOT) -> list[str]:
    home = Path.home() if home is None else home
    argv = ["bwrap", "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc", "--die-with-parent",
            "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
            "--tmpfs", str(home)]
    if not checkout.resolve().is_relative_to(home.resolve()):
        argv += ["--tmpfs", str(checkout.resolve())]
    toolchain_root = toolchain.parent
    argv += ["--ro-bind", str(toolchain_root), str(toolchain_root), "--bind", str(stage), str(stage),
             "--clearenv", "--setenv", "PATH", ":".join(str(p) for p in path)]
    for key, value in sorted(env.items()):
        argv += ["--setenv", key, value]
    argv += ["--chdir", str(cwd), "--"]
    return argv


def sandbox_probe() -> None:
    if shutil.which("bwrap") is None:
        raise Unusable("bwrap is not on PATH; the offline build is measured in a bwrap sandbox")
    probe = subprocess.run(["bwrap", "--unshare-user", "--unshare-net", "--unshare-pid", "--ro-bind", "/", "/",
                            "--dev", "/dev", "--proc", "/proc", "--", "true"],
                           capture_output=True, text=True, check=False)
    if probe.returncode != 0:
        raise Unusable(f"bwrap cannot make a user and network namespace here: {probe.stderr.strip()}")


def describe_checkout() -> str:
    return run(["git", *DESCRIBE], ROOT).strip()


def package_version(meta: dict[tuple[str, str], Package], reader: Path) -> tuple[str, Path] | None:
    """The package whose directory holds the commit variable's reader, and its version."""
    for (name, version), pkg in meta.items():
        if pkg.build_script is not None and pkg.build_script.resolve() == reader.resolve():
            return version, pkg.dir
    return None


def script_env(messages: str, package_dir: Path, name: str) -> list[str]:
    """The values of `name` the build script of the package at `package_dir` handed rustc, from
    cargo's JSON messages: one per `build-script-executed` of that package (one per feature set the
    build compiled it with). A package id is `path+file://<dir>#<name>@<version>`."""
    prefix = f"path+file://{package_dir}#"
    values: list[str] = []
    for line in messages.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") != "build-script-executed" or not str(msg.get("package_id", "")).startswith(prefix):
            continue
        values += [value for key, value in msg.get("env", []) if key == name]
    return values


def build(decl: dict, ids: list[str]) -> None:
    bundles = [b for b in decl["bundles"] if not ids or b["id"] in ids]
    unknown = sorted(set(ids) - {b["id"] for b in decl["bundles"]})
    if unknown:
        raise Unusable(f"no bundle {', '.join(unknown)} in the entry")
    sandbox_probe()
    graph, meta = check(decl)
    reader = package_version(meta, ROOT / decl["commit_input"]["read_by"])
    if reader is None:
        raise Finding(f"no package's build script is {decl['commit_input']['read_by']}")
    reader_version, reader_dir = reader
    commit = describe_checkout()
    expected = f"v{reader_version}-{commit}"

    stage = stage_root()
    src = stage / "src"
    stage_source(decl, src)
    crates_dir = vendor(decl, src, stage)
    bindir = toolchain_bin(decl["toolchain"]["channel"])
    path = [tool_dir(decl, stage, bundles), stub_dir(stage), bindir]
    target = stage / "target"
    calls = stage / "calls.log"
    env = {"HOME": str(stage / "home"), "CARGO_HOME": str(cargo_home(stage, crates_dir)),
           "CARGO_TARGET_DIR": str(target), "TMPDIR": "/tmp", "OFFLINE_BUILD_CALLS": str(calls),
           decl["commit_input"]["variable"]: commit}
    for key in CARRIED:
        if os.environ.get(key):
            env[key] = os.environ[key]
    (stage / "home").mkdir(exist_ok=True)
    logs = stage / "logs"
    logs.mkdir(exist_ok=True)
    workspace = src / Path(decl["cargo"]["manifest"]).parent
    failed: list[str] = []
    for b in bundles:
        calls.write_text("")
        argv = [str(bindir / "cargo"), "build", *decl["cargo"]["flags"], "-p", b["package"]]
        if b["features"]:
            argv += ["--features", ",".join(b["features"])]
        if not b["default_features"]:
            argv.append("--no-default-features")
        # The messages are cargo's own record of the build: `build-script-executed` carries the
        # environment each build script handed rustc, replayed for a script that did not run again.
        argv.append("--message-format=json-render-diagnostics")
        log = logs / f"{b['id']}.log"
        messages = logs / f"{b['id']}.messages.jsonl"
        print(f"  offline-build: {b['id']}: {' '.join(argv[1:])} (log {log})", flush=True)
        with log.open("w") as err, messages.open("w") as out:
            rc = subprocess.run(sandbox_argv(stage, bindir, path, env, workspace) + argv,
                                stdout=out, stderr=err, check=False).returncode
        problems: list[str] = []
        if rc != 0:
            tail = log.read_text(errors="replace").splitlines()[-40:]
            problems.append(f"cargo exited {rc}; the log ends:\n      " + "\n      ".join(tail))
        made = [c for c in calls.read_text().splitlines() if c]
        if made:
            problems.append("called a program a build with no network and no history must not: " + "; ".join(made))
        if rc == 0:
            for product in b["products"]:
                if not (target / "release" / product).is_file():
                    problems.append(f"declared product {product} is not in {target / 'release'}")
            holds_reader = any(meta.get(k) and meta[k].dir.resolve() == reader_dir.resolve()
                               for k in graph.packages[b["id"]])
            if holds_reader:
                staged_reader = src / reader_dir.resolve().relative_to(ROOT.resolve())
                given = script_env(messages.read_text(errors="replace"), staged_reader,
                                   decl["commit_input"]["rustc_env"])
                if given != [expected]:
                    problems.append(f"the build script of {staged_reader} handed rustc "
                                    f"{decl['commit_input']['rustc_env']}={given}, where a checkout build "
                                    f"of this tree composes [{expected!r}]")
        if problems:
            failed.append(b["id"])
            print(f"  offline-build FAIL {b['id']}:\n    " + "\n    ".join(problems), file=sys.stderr)
        else:
            print(f"  offline-build: {b['id']} built with no network, no .git and only the declared inputs")
    if failed:
        raise Finding(f"{len(failed)} of {len(bundles)} bundles failed the offline build: {', '.join(failed)}")


# ---------------------------------------------------------------------------------------------
# Self-test


def selftest() -> int:
    fails: list[str] = []
    ran = [0]

    def expect(label: str, ok: bool) -> None:
        ran[0] += 1
        if not ok:
            fails.append(label)

    decl = load()
    expect("the shipped entry has no shape finding", shape_findings(decl) == [])
    expect("a missing key is a shape finding",
           shape_findings({k: v for k, v in decl.items() if k != "linker"}) != [])
    bad = json.loads(json.dumps(decl))
    bad["build_scripts"]["ring"] = ["cc", "nasm"]
    expect("an undeclared tool is a shape finding", any("'nasm'" in p for p in shape_findings(bad)))
    bad = json.loads(json.dumps(decl))
    del bad["system_tools"]["cc"]["commands"]
    expect("a tool without its commands is a shape finding", any("'cc'" in p for p in shape_findings(bad)))
    bad = json.loads(json.dumps(decl))
    bad["bundles"][1]["features"] = ["lifecycle-doors", "identity-make"]
    expect("unsorted features are a shape finding", any("sorted" in p for p in shape_findings(bad)))

    expect("the channel is read from [toolchain]",
           toolchain_channel('[other]\nchannel = "x"\n[toolchain]\nchannel = "1.2.3"\n') == "1.2.3")
    expect("submodules are read from .gitmodules",
           gitmodules('[submodule "a"]\n\tpath = vendor/a\n\turl = https://e/a.git\n')
           == {"vendor/a": "https://e/a.git"})
    composed = 'try_to_find_and_link_lib("SNAPPY")\nenv::var(format!("{lib_name}_LIB_DIR"))'
    expect("a composed library variable is read", reads_variable(composed, "SNAPPY_LIB_DIR"))
    expect("a composed variable of another stem is not", not reads_variable(composed, "ZSTD_LIB_DIR"))
    msgs = "\n".join([
        json.dumps({"reason": "build-script-executed", "package_id": "path+file:///s/crates/z#zenoh@1.0.0",
                    "env": [["V", "v1.0.0-" + "a" * 40], ["OTHER", "x"]]}),
        json.dumps({"reason": "build-script-executed", "package_id": "path+file:///s/crates/zz#other@1.0.0",
                    "env": [["V", "v9"]]}),
        json.dumps({"reason": "compiler-artifact", "package_id": "path+file:///s/crates/z#zenoh@1.0.0"}),
        "not json",
    ])
    expect("a build script's rustc environment is read from cargo's messages, for that package only",
           script_env(msgs, Path("/s/crates/z"), "V") == ["v1.0.0-" + "a" * 40])
    expect("a tree listing is read once per package",
           parse_tree("a v1.0.0 (/x)\nb v2.0.0\na v1.0.0 (/x) (*)\nm v0.1.0 (proc-macro)\n")
           == [("a", "1.0.0"), ("b", "2.0.0"), ("m", "0.1.0")])

    root = Path("/fixture")
    meta = {("app", "0.1.0"): Package(root / "crates/app", root / "crates/app/build.rs"),
            ("cc-user", "1.0.0"): Package(Path("/reg/cc-user"), Path("/reg/cc-user/build.rs")),
            ("plain", "1.0.0"): Package(Path("/reg/plain"), None),
            ("sub", "0.1.0"): Package(root / "vendor/s/sub", None)}
    texts = {Path("/reg/cc-user/build.rs"): 'cc::Build::new(); env::var("CC_USER_LIB_DIR")',
             root / "crates/app/build.rs": "fn main() {}"}
    closures = {"one": [("app", "0.1.0"), ("cc-user", "1.0.0"), ("sub", "0.1.0")],
                "two": [("app", "0.1.0"), ("plain", "1.0.0")]}
    graph = derive(closures, meta, ["vendor/s", "vendor/t"], root, read=lambda p: texts[p])
    expect("build scripts are derived per bundle",
           graph.scripts == {"one": ["app", "cc-user"], "two": ["app"]})
    expect("a reached submodule is derived and an unreached one is not", graph.submodules == ["vendor/s"])

    fixture = {
        "toolchain": {"channel": "1.0.0"},
        "linker": "cc",
        "build_scripts": {"app": [], "cc-user": ["ar", "cc"]},
        "bundles": [{"id": "one", "system_tools": ["ar", "cc"]}, {"id": "two", "system_tools": ["cc"]}],
        "source": {"submodules": [{"path": "vendor/s", "url": "u"}]},
        "output_variables": {"names": ["CC_USER_LIB_DIR"]},
        "commit_input": {"variable": "THE_COMMIT", "read_by": "crates/app/build.rs", "rustc_env": "APP_VERSION"},
        "not_inputs": [{"id": "oracle", "list": "bash scripts/get.sh --inputs", "hand_in": ["ORACLE_ARCHIVE"]}],
    }
    files = {"crates/app/build.rs": "THE_COMMIT APP_VERSION", "scripts/get.sh": "ORACLE_ARCHIVE"}
    modules = {"vendor/s": "u"}

    def found(d: dict, lock: str = "", fs: dict | None = None, g: Graph = graph) -> list[str]:
        table = files if fs is None else fs
        return findings(d, g, "1.0.0", modules, lock, lambda rel: table.get(rel))

    expect("a matching fixture has no finding", found(fixture) == [])

    def mutated(path: list, value) -> dict:
        d = json.loads(json.dumps(fixture))
        node = d
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
        return d

    cases = [
        ("a crate with a build script and no row", mutated(["build_scripts"], {"app": []}), "no `build_scripts` row"),
        ("a row no closure builds", mutated(["build_scripts", "gone"], []), "no bundle's closure"),
        ("a bundle missing a tool", mutated(["bundles", 0, "system_tools"], ["cc"]), "its closure needs"),
        ("a bundle with a tool it does not need", mutated(["bundles", 1, "system_tools"], ["ar", "cc"]),
         "its closure needs"),
        ("a submodule not declared", mutated(["source", "submodules"], []), "the closures reach"),
        ("a submodule url that moved", mutated(["source", "submodules", 0, "url"], "v"), ".gitmodules says"),
        ("a channel that moved", mutated(["toolchain", "channel"], "2.0.0"), "rust-toolchain.toml pins"),
        ("an output variable nothing reads", mutated(["output_variables", "names"], ["NOBODY_READS"]),
         "no build script"),
        ("a commit variable the reader does not name", mutated(["commit_input", "variable"], "OTHER"),
         "does not name"),
        ("a hand-in variable the script does not take",
         mutated(["not_inputs", 0, "hand_in"], ["NOT_TAKEN"]), "does not take"),
    ]
    for label, d, needle in cases:
        expect(label, any(needle in f for f in found(d)))
    expect("a git source in the lockfile is a finding",
           any("git source" in f for f in found(fixture, 'source = "git+https://e/x"\n')))
    reading = Graph(scripts=graph.scripts, packages=graph.packages, submodules=graph.submodules,
                    script_texts={**graph.script_texts, "app": "ORACLE_ARCHIVE"})
    expect("a build script that reads a not-input's variable is a finding",
           any("so it is an input" in f for f in found(fixture, g=reading)))

    with tempfile.TemporaryDirectory() as tmp:
        src, dest = Path(tmp) / "src", Path(tmp) / "dest"
        (src / "a").mkdir(parents=True)
        (src / "a/one").write_text("1")
        (src / "two").write_text("2")
        os.symlink("two", src / "link")
        (dest / "stale/deep").mkdir(parents=True)
        (dest / "stale/deep/x").write_text("x")
        copied, removed = sync_tree(src, ["a/one", "two", "link", "absent"], dest)
        expect("sync copies every listed file and the link", copied == 3 and (dest / "a/one").read_text() == "1"
               and os.readlink(dest / "link") == "two")
        expect("sync removes what is not listed, and the empty directories", removed == 1
               and not (dest / "stale").exists())
        expect("sync leaves an unchanged file alone", sync_tree(src, ["a/one", "two", "link"], dest) == (0, 0))
        (src / "two").write_text("22")
        expect("sync copies a changed file", sync_tree(src, ["a/one", "two", "link"], dest) == (1, 0)
               and (dest / "two").read_text() == "22")

    home = Path("/home/u")
    argv = sandbox_argv(Path("/home/u/.cache/s"), Path("/tc/bin"), [Path("/p")], {"K": "v"}, Path("/w"),
                        home=home, checkout=Path("/home/u/repo"))
    expect("the sandbox has no network and an empty home", "--unshare-net" in argv
           and argv[argv.index("--tmpfs", argv.index("/tmp")) + 1] == "/home/u")
    expect("a checkout under the home is covered by the home's tmpfs, and not twice",
           argv.count("--tmpfs") == 2)
    argv = sandbox_argv(Path("/c/s"), Path("/tc/bin"), [Path("/p")], {}, Path("/w"), home=home,
                        checkout=Path("/srv/repo"))
    expect("a checkout elsewhere is covered by its own tmpfs", "/srv/repo" in argv)
    expect("the environment is cleared", "--clearenv" in argv)
    try:
        # Any path under the checkout is refused; this one names no product
        # directory, so the artifact-root lint has nothing to read into it.
        stage_root({"WZ_OFFLINE_BUILD_ROOT": str(ROOT / "staged-inside-the-checkout")})
        refused = False
    except Unusable:
        refused = True
    expect("a staging root inside the checkout is refused", refused)

    if fails:
        for f in fails:
            print(f"offline_build selftest FAIL: {f}", file=sys.stderr)
        return 1
    print(f"offline_build selftest: OK ({ran[0]} cases)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--build", action="store_true")
    mode.add_argument("--selftest", action="store_true")
    ap.add_argument("--bundle", action="append", default=[], help="with --build: one bundle id (repeatable)")
    args = ap.parse_args()
    try:
        if args.selftest:
            return selftest()
        decl = load()
        if args.check:
            graph, _ = check(decl)
            union = {n for names in graph.scripts.values() for n in names}
            print(f"offline_build: OK ({len(decl['bundles'])} bundles, {len(union)} build scripts, "
                  f"submodules {', '.join(graph.submodules) or 'none'})")
            return 0
        build(decl, args.bundle)
        return 0
    except Finding as e:
        print(f"offline_build FAIL: {e}", file=sys.stderr)
        return 1
    except Unusable as e:
        print(f"offline_build: cannot run: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
