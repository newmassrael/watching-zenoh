#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4175 (no register item) -- the server layer sits above the session engine, never below it.

The owner asked on 2026-11-03 for the server layer to be split out of
`wz-session-core`: storage (the `storage_*` modules), the admin space
(`adminspace`, `admin_*`) and the auth methods that are not the transport
handshake (`extauth_*`). They move into crates of their own in this workspace
(`wz-storage`, `wz-admin`, `wz-auth`), one landable step at a time, and each of
those crates depends on the core. The split is worth something only while the
dependency points one way: a core that names an upper crate again, through a
dependency edge or a path in its source, has folded the layers back into one,
and nothing in the build would refuse it, because Cargo accepts any acyclic
graph and a dev-dependency is not even a cycle.

## What is checked

1. THE MODULES STILL IN CORE. A module of `crates/wz-session-core/src` (a
   `<stem>.rs` file or a `<stem>/` directory) whose stem is a server-layer stem
   (`storage_*`, `admin*`, `extauth_*`) must be named in `IN_CORE`, the list of
   the server modules not yet moved. A server module that is not in the list is a
   new one written into the core: it belongs in its upper crate. A name in the list
   with no module behind it has moved: the list is a ratchet and only shrinks, so
   the step that moves a module removes its name here in the same change. Stems
   that stay are not server-layer by this rule: `auth_dispatch` and `extauth` are
   the transport handshake's sub-extension, demuxed per frame by the drive loop.
2. THE GRAPH, as `cargo metadata` of the `crates/` workspace reads it (the
   manifests are not parsed here: cargo already knows what each one declares,
   renames and target tables included). The core has no dependency of any kind
   (normal, build, dev, any target's) on an upper crate; a dev edge would compile
   the core twice in one test binary, two copies of every type, which is why a
   core test that needs an upper crate moves to that crate instead. Each upper
   crate that is a workspace member has a normal dependency on the core.
3. THE SOURCE. No Rust file under `crates/wz-session-core` names an upper
   crate's path (`wz_auth::`, `wz_storage::`, `wz_admin::`, or `extern crate` of
   one). The graph rule already makes such a path fail to compile; this rule names
   the line, and it holds in a reduced build where the line is behind a feature no
   build turns on.

A population of zero is a FAIL, not a pass: no workspace member, no core among
them, or no core source file means nothing was measured.

## Modes

`--check` grades the tracked tree. `--selftest` drives the same grading over
fixture metadata and fixture source trees, red-first. There is no default mode: a
missing or unknown argument is refused by name.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

import cargo_workspaces

ROOT = Path(__file__).resolve().parents[2]

CORE = "wz-session-core"

# Each upper crate's package name and the identifier its library is named by.
UPPER = {
    "wz-auth": "wz_auth",
    "wz-storage": "wz_storage",
    "wz-admin": "wz_admin",
}

# A module stem is server-layer when it matches this. `extauth` itself and
# `auth_dispatch` do not: they are the transport handshake and stay in core.
SERVER_STEM = re.compile(r"^(?:storage_\w+|admin\w*|extauth_\w+)$")

# The server modules not yet moved. A ratchet: a step that moves a module
# deletes its name here, and nothing is ever added.
IN_CORE = frozenset(
    {
        "admin_config_space",
        "admin_connect",
        "admin_reply",
        "adminspace",
        "storage_aligner",
        "storage_backend",
        "storage_config",
        "storage_history",
        "storage_plugin_config",
        "storage_replication",
        "storage_state",
        "storage_strip_prefix",
        "storage_volume",
    }
)

UPPER_PATH = re.compile(
    r"\b(?:extern\s+crate\s+(?:" + "|".join(UPPER.values()) + r")\b|(?:"
    + "|".join(UPPER.values())
    + r")\s*::)"
)


class InputError(Exception):
    """An input this gate could not read. Reported as a FAIL, never a traceback."""


def _kind(dep: dict) -> str:
    kind = dep.get("kind") or "normal"
    target = dep.get("target")
    return f"{kind} ({target})" if target else kind


def members(meta: dict) -> dict[str, dict]:
    """`{package name: package}` of the workspace's members."""
    ids = set(meta.get("workspace_members", []))
    return {p["name"]: p for p in meta.get("packages", []) if p.get("id") in ids}


def server_modules(src: Path) -> set[str]:
    """The server-layer module stems under a crate's `src`."""
    stems = set()
    for entry in src.iterdir():
        if entry.is_file() and entry.suffix == ".rs":
            stem = entry.stem
        elif entry.is_dir():
            stem = entry.name
        else:
            continue
        if SERVER_STEM.match(stem):
            stems.add(stem)
    return stems


def grade(meta: dict, in_core: frozenset[str]) -> tuple[list[str], str]:
    """The findings over a workspace's metadata and its core's source, and a census."""
    findings: list[str] = []
    pkgs = members(meta)
    if not pkgs:
        raise InputError("the workspace metadata lists no member package")
    if CORE not in pkgs:
        raise InputError(f"{CORE} is not a workspace member")
    core_dir = Path(pkgs[CORE]["manifest_path"]).parent
    core_src = core_dir / "src"
    if not core_src.is_dir():
        raise InputError(f"{core_src}: no source directory")

    # 1. The modules still in core.
    found = server_modules(core_src)
    for stem in sorted(found - in_core):
        findings.append(
            f"{CORE}/src/{stem} is a server-layer module that is not in IN_CORE: "
            f"write it in its upper crate ({', '.join(UPPER)}), not in the core"
        )
    for stem in sorted(in_core - found):
        findings.append(
            f"IN_CORE names {stem}, and {CORE}/src has no such module: it has moved, "
            f"so delete its name from IN_CORE (the list only shrinks)"
        )

    # 2. The graph.
    for dep in pkgs[CORE].get("dependencies", []):
        if dep.get("name") in UPPER:
            findings.append(
                f"{CORE} has a {_kind(dep)} dependency on {dep['name']}: the core never "
                f"depends on an upper crate (a test that needs it moves to {dep['name']})"
            )
    present_upper = [u for u in UPPER if u in pkgs]
    for upper in present_upper:
        normal = {
            d.get("name")
            for d in pkgs[upper].get("dependencies", [])
            if not d.get("kind") and not d.get("target")
        }
        if CORE not in normal:
            findings.append(
                f"{upper} has no normal dependency on {CORE}: an upper crate is built "
                f"on the core"
            )

    # 3. The source.
    rust_files = sorted(
        p for p in core_dir.rglob("*.rs") if "target" not in p.relative_to(core_dir).parts
    )
    if not rust_files:
        raise InputError(f"{core_dir}: no Rust source")
    for path in rust_files:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if UPPER_PATH.search(line):
                rel = path.relative_to(core_dir.parent)
                findings.append(
                    f"{rel}:{lineno} names an upper crate's path: {line.strip()[:120]}"
                )

    census = (
        f"{len(found)} server module(s) still in {CORE} of {len(in_core)} listed; "
        f"{len(present_upper)} of {len(UPPER)} upper crate(s) built; "
        f"{len(rust_files)} core Rust file(s) read"
    )
    return findings, census


def check() -> int:
    try:
        meta = cargo_workspaces.metadata("crates")
        findings, census = grade(meta, IN_CORE)
    except (InputError, RuntimeError, OSError) as e:
        print(f"layer-direction: FAIL -- cannot grade: {e}", file=sys.stderr)
        return 1
    if findings:
        print("layer-direction: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        print(f"layer-direction: {census}", file=sys.stderr)
        return 1
    print(f"layer-direction: OK -- {census}")
    return 0


def _dep(name: str, kind: str | None = None, target: str | None = None) -> dict:
    return {"name": name, "kind": kind, "target": target}


def _fixture(
    root: Path,
    *,
    core_modules: tuple[str, ...] = ("storage_manager", "extauth", "auth_dispatch"),
    core_deps: tuple[dict, ...] = (),
    upper: dict[str, tuple[dict, ...]] | None = None,
    core_line: str = "",
) -> dict:
    """A core source tree under `root` and the metadata a workspace of it reads as."""
    upper = upper or {}
    src = root / CORE / "src"
    src.mkdir(parents=True)
    (src / "lib.rs").write_text("pub fn f() {}\n" + core_line, encoding="utf-8")
    for stem in core_modules:
        (src / f"{stem}.rs").write_text("\n", encoding="utf-8")
    packages = [
        {
            "name": CORE,
            "id": CORE,
            "manifest_path": str(root / CORE / "Cargo.toml"),
            "dependencies": list(core_deps),
        }
    ]
    for name, deps in upper.items():
        packages.append(
            {
                "name": name,
                "id": name,
                "manifest_path": str(root / name / "Cargo.toml"),
                "dependencies": list(deps),
            }
        )
    return {"packages": packages, "workspace_members": [p["id"] for p in packages]}


def selftest() -> int:
    listed = frozenset({"storage_manager"})
    # (name, fixture arguments, should_fail, substring a finding carries)
    rows = [
        ("agrees", {}, False, ""),
        (
            "a new server module in core",
            {"core_modules": ("storage_manager", "storage_new", "extauth")},
            True,
            "storage_new is a server-layer module",
        ),
        (
            "an admin module by its bare prefix",
            {"core_modules": ("storage_manager", "adminspace")},
            True,
            "adminspace is a server-layer module",
        ),
        (
            "an auth method beside the handshake",
            {"core_modules": ("storage_manager", "extauth_pubkey", "extauth")},
            True,
            "extauth_pubkey is a server-layer module",
        ),
        (
            "a listed module that moved",
            {"core_modules": ("extauth",)},
            True,
            "delete its name from IN_CORE",
        ),
        (
            "the core depends on an upper crate",
            {"core_deps": (_dep("wz-auth"),)},
            True,
            "normal dependency on wz-auth",
        ),
        (
            "a dev edge from the core",
            {"core_deps": (_dep("wz-storage", "dev"),)},
            True,
            "dev dependency on wz-storage",
        ),
        (
            "a target edge from the core",
            {"core_deps": (_dep("wz-admin", "build", "cfg(unix)"),)},
            True,
            "build (cfg(unix)) dependency on wz-admin",
        ),
        (
            "an upper crate built on the core",
            {"upper": {"wz-auth": (_dep(CORE),)}},
            False,
            "",
        ),
        (
            "an upper crate not built on the core",
            {"upper": {"wz-auth": ()}},
            True,
            "no normal dependency on",
        ),
        (
            "an upper crate that reaches the core only in its tests",
            {"upper": {"wz-auth": (_dep(CORE, "dev"),)}},
            True,
            "no normal dependency on",
        ),
        (
            "the core names an upper path",
            {"core_line": "use wz_storage::Volume;\n"},
            True,
            "names an upper crate's path",
        ),
        (
            "the core names an upper crate by extern",
            {"core_line": "extern crate wz_admin;\n"},
            True,
            "names an upper crate's path",
        ),
        (
            "prose that names a crate is not a path",
            {"core_line": "// moved to the wz-auth crate (wz_auth)\n"},
            False,
            "",
        ),
    ]
    bad = 0
    for name, kwargs, should_fail, needle in rows:
        with tempfile.TemporaryDirectory() as tmp:
            meta = _fixture(Path(tmp), **kwargs)
            findings, _census = grade(meta, listed)
        failed = bool(findings)
        ok = failed == should_fail and (not should_fail or any(needle in f for f in findings))
        print(f"  selftest {'ok  ' if ok else 'BAD '} {name}: "
              f"{'refused' if failed else 'accepted'}")
        if not ok:
            bad += 1
            for f in findings:
                print(f"      {f}", file=sys.stderr)

    # A population of zero is refused, not passed.
    zero_rows = [
        ("no workspace member", lambda m: m.update(workspace_members=[]),
         "no member package"),
        ("the core is not a member", lambda m: m.update(workspace_members=["other"]),
         "no member package"),
        ("the core is missing among members",
         lambda m: m["packages"].append({"name": "other", "id": "other"})
         or m.update(workspace_members=["other"]),
         "not a workspace member"),
    ]
    for name, spoil, needle in zero_rows:
        with tempfile.TemporaryDirectory() as tmp:
            meta = _fixture(Path(tmp))
            spoil(meta)
            try:
                grade(meta, listed)
                ok = False
            except InputError as e:
                ok = needle in str(e)
        print(f"  selftest {'ok  ' if ok else 'BAD '} {name}: refused")
        if not ok:
            bad += 1

    # The tracked list must name only server-layer stems; otherwise a typo in
    # IN_CORE would be a name the module rule could never reach.
    stray = sorted(s for s in IN_CORE if not SERVER_STEM.match(s))
    if stray:
        print(f"  selftest BAD  IN_CORE names non-server stems: {stray}", file=sys.stderr)
        bad += 1
    else:
        print("  selftest ok   IN_CORE names only server-layer stems")

    if bad:
        print(f"  layer-direction selftest FAIL: {bad} row(s)", file=sys.stderr)
        return 1
    print("  layer-direction selftest: every row held")
    return 0


def main(argv: list[str]) -> int:
    modes = {"--check": check, "--selftest": selftest}
    if len(argv) != 2 or argv[1] not in modes:
        print(
            "usage: layer_direction_gate.py --check | --selftest "
            "(a mode is required; there is no default)",
            file=sys.stderr,
        )
        return 2
    return modes[argv[1]]()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
