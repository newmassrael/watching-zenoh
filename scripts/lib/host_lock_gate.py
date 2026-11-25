#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4636 (no register item) -- a crate the cooperative C ABI links holds the host's lock
(`wz-host-sync`), never `std`'s.

## Why

A C ABI library over the cooperative engine takes no memory once a session is open, on every host.
`std`'s lock, condition variable and reader-writer lock do not keep that on every host: where the
system waits on an address (Linux's futex, Windows' slim lock) they lie in their own bytes, but on
macOS and QNX they are pthread objects, which must not move once used, so `std` boxes each the
first time it is taken. A lock made after the open (a subscriber's state, a sender's handle, a
supervisor) then allocates on its first take, on those hosts only, where no Linux row looks.

`wz-host-sync`'s `Mutex`, `Condvar` and `RwLock` are the one name for a lock there: `std`'s where
`std`'s lie in their own bytes, the in-place ones elsewhere (crates/wz-host-sync/src/lib.rs), and
`wz_capi_port::os` names the same ones. This gate makes the rule a Linux verdict: the crates of the
library name `std`'s lock in one file, the one that chooses it.

## The population

Every workspace member the cooperative pico C ABI links: what `cargo tree -e normal` resolves for
`wz-capi-pico` under its `coop` documentation set (`[package.metadata.wz-docs]`, read by
`doc_feature_sets.py`: every feature but the tokio engine's), so a crate that set reaches is held
and the tokio engine's crates are not. Their `src/**.rs`, minus every file and item that exists
only in a test build (`subsystem_spawn_gate`'s reader, so the gates agree on what test code is):
a test may hold `std`'s lock, and the test binaries count what the host's lock takes.

A population without `wz-host-sync` is a FAIL: the door is not linked, so nothing was measured.

## What is refused

Outside a comment and a string literal, anywhere but in `ALLOWED`:

  * a path to `std::sync::Mutex`, `Condvar`, `RwLock` or `Barrier` (a barrier is a lock and a
    condition variable), and a use tree of `std::sync` that imports one of them;
  * a rename of `std::sync` (`as`, `self as`), its import as a module and a glob import of it,
    after which this gate cannot see which item a later line names.

A file in `ALLOWED` is held to the number of places it names, both ways: one more is refused as a
new lock past the door, one fewer as an entry to shrink.

What this cannot see, stated rather than implied: a lock a macro of another crate expands into a
crate of the population, a crate of the population reached only under a target the tree is not
asked for (the tree resolves the host it runs on), and `std`'s lock reached through a type of a
crate outside the population.

Usage:
    python3 scripts/lib/host_lock_gate.py --check
    python3 scripts/lib/host_lock_gate.py --selftest
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cargo_workspaces  # noqa: E402  -- after the path insert that finds it
import doc_feature_sets  # noqa: E402
import rust_comments  # noqa: E402
from subsystem_spawn_gate import cfg_test_files, cfg_test_spans  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The library whose graph is the population, and its documentation set that is the cooperative
#: engine's.
LIBRARY = "wz-capi-pico"
FEATURE_SET = "coop"
#: The crate the lock comes from; a population without it measured nothing.
DOOR = "wz-host-sync"

#: (path relative to the root) -> (how many places name `std`'s lock there, the reason).
ALLOWED: dict[str, tuple[int, str]] = {
    "crates/wz-host-sync/src/std_lock.rs": (
        6,
        "the door: `std`'s lock, condition variable and reader-writer lock, which the crate root "
        "chooses in a build with `std` on a host where they lie in their own bytes",
    ),
    "crates/wz-session-core/src/session_actions.rs": (
        2,
        "the link set of `transport-multilink`, which only the tokio runtime builds (it needs "
        "`std` and an RSA handshake): the cooperative C ABI's graph never selects the feature",
    ),
}

_STD_SYNC = r"(?<![\w])std\s*::\s*sync"
_LOCKS = r"(?:Mutex|Condvar|RwLock|Barrier)\b"

#: What names `std`'s lock, or hides that a later line does.
PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(_STD_SYNC + r"\s*::\s*" + _LOCKS),
    re.compile(
        _STD_SYNC + r"\s*::\s*\{(?:[^{}]|\{[^{}]*\})*?\b" + _LOCKS + r"(?:[^{}]|\{[^{}]*\})*\}"
    ),
    re.compile(_STD_SYNC + r"\s+as\s+[A-Za-z_]\w*"),
    re.compile(_STD_SYNC + r"\s*::\s*\{(?:[^{}]|\{[^{}]*\})*?\bself\b(?:[^{}]|\{[^{}]*\})*\}"),
    re.compile(_STD_SYNC + r"\s*::\s*\*"),
    re.compile(r"\buse\s+" + _STD_SYNC + r"\s*;"),
)


class InputError(Exception):
    """An input this gate could not read. Reported as a FAIL, never a traceback."""


def library_features(meta: dict) -> list[str]:
    """The features of `LIBRARY`'s `FEATURE_SET` documentation set."""
    for pkg in meta.get("packages", []):
        if pkg.get("name") != LIBRARY:
            continue
        try:
            sets = dict(doc_feature_sets.documentation_sets(pkg))
        except doc_feature_sets.ManifestError as e:
            raise InputError(f"{LIBRARY}'s documentation sets: {e}") from e
        if FEATURE_SET not in sets:
            raise InputError(f"{LIBRARY} declares no `{FEATURE_SET}` documentation set")
        return list(sets[FEATURE_SET])
    raise InputError(f"{LIBRARY} is not a workspace member; nothing was measured")


def library_tree(features: list[str]) -> str:
    """`cargo tree` of `LIBRARY`'s normal dependencies under `features`, one package a line."""
    cmd = [
        "cargo", "tree", "-p", LIBRARY, "-e", "normal", "--prefix", "none", "-f", "{p}",
        "--no-default-features",
    ]
    if features:
        cmd += ["--features", ",".join(features)]
    proc = subprocess.run(
        cmd, cwd=REPO_ROOT / "crates", capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise InputError(f"`cargo tree` failed (rc={proc.returncode}): {proc.stderr.strip()[:400]}")
    return proc.stdout


def population(meta: dict, tree: str) -> dict[str, Path]:
    """`{crate: its src directory}` of the workspace members `tree` names."""
    ids = set(meta.get("workspace_members", []))
    members = {
        pkg["name"]: Path(pkg["manifest_path"]).parent / "src"
        for pkg in meta.get("packages", [])
        if pkg.get("id") in ids
    }
    named = {line.split()[0] for line in tree.splitlines() if line.strip()}
    crates = {name: src for name, src in members.items() if name in named}
    if DOOR not in crates:
        raise InputError(f"{LIBRARY}'s graph does not reach {DOOR}; nothing was measured")
    return crates


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def places(root: Path, crates: dict[str, Path]) -> list[tuple[str, int, str]]:
    """Every place production code of `crates` names `std`'s lock or hides that it does:
    (path relative to `root`, line, the text)."""
    found: list[tuple[str, int, str]] = []
    for name, src in sorted(crates.items()):
        if not src.is_dir():
            raise InputError(f"{name}: no source directory at {src}")
        files = sorted(src.rglob("*.rs"))
        test_only = cfg_test_files(files)
        for path in files:
            if path.resolve() in test_only:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            stripped = rust_comments.strip_comments(text, blank_literals=True)
            skip = cfg_test_spans(stripped)
            rel = _rel(path, root)
            seen: set[int] = set()
            for pattern in PATTERNS:
                for m in pattern.finditer(stripped):
                    if m.start() in seen or any(a <= m.start() <= b for a, b in skip):
                        continue
                    seen.add(m.start())
                    line = stripped.count("\n", 0, m.start()) + 1
                    found.append((rel, line, " ".join(m.group(0).split())))
    return sorted(found)


def grade(
    root: Path, meta: dict, tree: str, allowed: dict[str, tuple[int, str]]
) -> tuple[list[str], int, int]:
    """The findings over `root`, `meta` and `tree` against `allowed`, the population's size and
    how many places were found."""
    findings: list[str] = []
    for rel, (_, reason) in allowed.items():
        if not reason.strip():
            findings.append(f"the allowed file {rel} states no reason")
    crates = population(meta, tree)
    found = places(root, crates)
    counted: dict[str, int] = {}
    for rel, line, text in found:
        if rel in allowed:
            counted[rel] = counted.get(rel, 0) + 1
            continue
        findings.append(
            f"{rel}:{line} names `std`'s lock ({text}); hold `wz_host_sync::{{Mutex, Condvar, "
            f"RwLock}}` (or `wz_capi_port::os`'s), which takes no memory when first taken on "
            f"any host, where `std`'s boxes a pthread object on macOS"
        )
    for rel, (want, _) in sorted(allowed.items()):
        have = counted.get(rel, 0)
        if have > want:
            findings.append(
                f"the allowed file {rel} names `std`'s lock in {have} places and the list allows "
                f"{want}: a lock past the door"
            )
        elif have < want:
            findings.append(
                f"the allowed file {rel} names `std`'s lock in {have} places and the list allows "
                f"{want}; lower its count, or take it off ALLOWED at 0"
            )
    return findings, len(crates), len(found)


def check() -> int:
    try:
        meta = cargo_workspaces.metadata("crates")
        tree = library_tree(library_features(meta))
        findings, crates, found = grade(REPO_ROOT, meta, tree, ALLOWED)
    except (InputError, RuntimeError, OSError) as e:
        print(f"host-lock: FAIL -- cannot grade: {e}", file=sys.stderr)
        return 1
    if findings:
        print("host-lock: FAIL", file=sys.stderr)
        for line in findings:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print(
        f"host-lock: OK -- {crates} crate(s) the cooperative C ABI links, {found} place(s) naming "
        f"`std`'s lock, each counted in one of {len(ALLOWED)} allowed file(s)"
    )
    return 0


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _package(root: Path, name: str) -> dict:
    return {
        "name": name,
        "id": f"{name} 0.1.0",
        "manifest_path": str(root / "crates" / name / "Cargo.toml"),
        "dependencies": [],
    }


DOOR_SRC = "pub struct Mutex<T>(std::sync::Mutex<T>);\n"
SHELL = (
    "use std::sync::{Arc, OnceLock};\n"
    "use std::sync::atomic::{AtomicBool, Ordering};\n"
    "use wz_host_sync::{Mutex, MutexGuard};\n"
    "// std::sync::Mutex in a comment is prose.\n"
    "pub fn quoted() -> &'static str {\n    \"std::sync::Mutex\"\n}\n"
    "pub fn guard(m: &std::sync::MutexGuard<'_, u8>) -> u8 {\n    **m\n}\n"
    "#[cfg(test)]\nmod tests {\n    use std::sync::{Condvar, Mutex};\n}\n"
    "#[cfg(all(feature = \"x\", test))]\nmod more;\n"
)
TEST_FILE = "use std::sync::Mutex;\n"


def _fixture(root: Path, *, door: str = DOOR_SRC, shell_extra: str = "", door_in_tree: bool = True):
    """A workspace under `root`, the metadata it reads as and the tree of the library: the door, a
    shell the library reaches, and a crate off the library's graph that holds `std`'s lock."""
    _write(root, f"crates/{DOOR}/src/lib.rs", "mod std_lock;\n")
    _write(root, f"crates/{DOOR}/src/std_lock.rs", door)
    _write(root, "crates/shell/src/lib.rs", SHELL + shell_extra)
    _write(root, "crates/shell/src/more.rs", TEST_FILE)
    _write(root, "crates/tokio-only/src/lib.rs", "static L: std::sync::Mutex<()> = std::sync::Mutex::new(());\n")
    packages = [_package(root, name) for name in (DOOR, "shell", "tokio-only")]
    meta = {"packages": packages, "workspace_members": [p["id"] for p in packages]}
    tree = "\n".join(
        [f"{LIBRARY} v0.1.0 (/x)", "shell v0.1.0 (/x)"]
        + ([f"{DOOR} v0.1.0 (/x)", f"{DOOR} v0.1.0 (/x) (*)"] if door_in_tree else [])
    )
    return meta, tree


def selftest() -> int:
    """Drive every rule over a fixture workspace, in both directions."""
    failures: list[str] = []
    allowed = {f"crates/{DOOR}/src/std_lock.rs": (1, "the door")}
    shell = "crates/shell/src/lib.rs"
    at = SHELL.count("\n") + 1
    # (name, fixture arguments, a substring one finding carries, or None for no finding)
    rows: list[tuple[str, dict, str | None]] = [
        ("agrees", {}, None),
        ("a path", {"shell_extra": "static L: std::sync::Mutex<u8> = todo!();\n"}, f"{shell}:{at} "),
        ("a use", {"shell_extra": "use std::sync::Condvar;\n"}, "(std::sync::Condvar)"),
        ("a leading root", {"shell_extra": "use ::std::sync::RwLock;\n"}, "(std::sync::RwLock)"),
        ("a barrier", {"shell_extra": "use std::sync::Barrier;\n"}, "(std::sync::Barrier)"),
        (
            "a use tree",
            {"shell_extra": "use std::sync::{Arc, Mutex};\n"},
            "(std::sync::{Arc, Mutex})",
        ),
        (
            "a nested use tree",
            {"shell_extra": "use std::sync::{\n    atomic::{AtomicU8, Ordering},\n    RwLock,\n};\n"},
            f"{shell}:{at} ",
        ),
        ("a rename", {"shell_extra": "use std::sync as s;\n"}, "(std::sync as s)"),
        (
            "a rename in a use tree",
            {"shell_extra": "use std::sync::{self as s, Arc};\n"},
            "(std::sync::{self as s, Arc})",
        ),
        ("a glob", {"shell_extra": "use std::sync::*;\n"}, "(std::sync::*)"),
        ("the module", {"shell_extra": "use std::sync;\n"}, "(use std::sync;)"),
        (
            "one more in the door",
            {"door": DOOR_SRC + "pub struct Condvar(std::sync::Condvar);\n"},
            "in 2 places and the list allows 1: a lock past the door",
        ),
        (
            "the door no longer names it",
            {"door": "pub struct Mutex<T>(T);\n"},
            "in 0 places and the list allows 1;",
        ),
    ]
    for name, kwargs, want in rows:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            meta, tree = _fixture(root, **kwargs)
            try:
                findings, crates, found = grade(root, meta, tree, allowed)
            except InputError as e:
                failures.append(f"{name}: cannot grade: {e}")
                continue
        if want is None:
            if findings:
                failures.append(f"{name}: want no finding, got {findings}")
            if (crates, found) != (2, 1):
                failures.append(f"{name}: want 2 crates and the door's 1 place, got {crates} and {found}")
        elif len(findings) != 1 or want not in findings[0]:
            failures.append(f"{name}: want one finding carrying {want!r}, got {findings}")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        meta, tree = _fixture(root, door_in_tree=False)
        try:
            grade(root, meta, tree, allowed)
            failures.append("a graph without the door is graded; it measured nothing")
        except InputError:
            pass
        meta, tree = _fixture(root)
        findings, _, _ = grade(root, meta, tree, {**allowed, shell: (0, " ")})
        if not any("states no reason" in f for f in findings):
            failures.append(f"an allowed file with no reason is refused, got {findings}")

    for rel, (count, reason) in ALLOWED.items():
        if not (REPO_ROOT / rel).is_file():
            failures.append(f"ALLOWED names {rel}, which is not a file")
        if count < 1:
            failures.append(f"ALLOWED entry {rel} allows no place; take it off the list")
        if not reason.strip():
            failures.append(f"ALLOWED entry {rel} states no reason")

    if failures:
        for line in failures:
            print(f"host-lock: SELFTEST FAIL -- {line}", file=sys.stderr)
        return 1
    print(f"host-lock: selftest OK -- {len(rows)} fixture rows and the refused inputs")
    return 0


def main(argv: list[str]) -> int:
    modes = {"--check": check, "--selftest": selftest}
    if len(argv) != 2 or argv[1] not in modes:
        print(
            "usage: host_lock_gate.py --check | --selftest "
            "(a mode is required; there is no default)",
            file=sys.stderr,
        )
        return 2
    return modes[argv[1]]()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
