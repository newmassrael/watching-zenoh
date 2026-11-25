#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4639 (no register item) -- a crate a library without a logger can link reaches the `log`
facade only through the session core's diagnostics (`wz_session_core::diag`).

## Why

The C ABI's cooperative library installs no logger, as zenoh-pico built without a log level has
no log call, and its size case refuses the facade (`LOG_FACADE` in `capability_cost_gate.py`).
`diag_warn!` and `diag_debug!` are the one door: with `wz-session-core`'s `log` feature each is the
facade's macro, without it each compiles to nothing, so the build that wants records turns one
feature on and a build that does not links nothing of it. A `log::warn!` written past the door,
or a crate that names `log` as a dependency of its own (an optional one a feature turns on too),
puts the facade back in every build that compiles the line, and only a size reading of a build
that enables it notices. This gate makes the rule a static verdict.

## The population

Every member of the `crates` workspace but the crates in `EXEMPT`: their `src/**.rs`, minus every file
and item that exists only in a test build (`subsystem_spawn_gate`'s reader, so the gates agree on
what test code is), and their manifests' normal dependencies. A crate is exempt only when it is a
host's alone: a member, outside the graph `cargo tree` resolves for `wz-capi-pico` under its `coop`
documentation set (every feature but the tokio engine's, the set `host_lock_gate` reads), and
calling the facade somewhere, or its entry is one to remove.

## What is refused

Outside a comment and a string literal, in a file that does not declare a module of its own named
`log` (where `log::` names that module), anywhere but in `ALLOWED`:

  * a macro of the facade called by its path (`log::warn!`, `::log::debug!`, `log::log_enabled!`);
  * an import from it (`use log::..`, `use log as ..`, `use log;`) and `extern crate log`, after
    which this gate cannot see which name a later line calls.

A file in `ALLOWED` is held to the number of places it names, both ways. A normal dependency named
`log`, optional or not, is refused outside `LOG_DEPENDENCY`, and an entry there whose crate no
longer names it is refused as one to remove.

What this cannot see, stated rather than implied: the facade reached through a crate outside the
workspace (the statechart runtime calls it with no feature of its own to leave it out), a
re-export of it under another name in a crate of the population, and a macro of another crate that
expands into a facade call.

Usage:
    python3 scripts/lib/log_facade_gate.py --check
    python3 scripts/lib/log_facade_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cargo_workspaces  # noqa: E402  -- after the path insert that finds it
import host_lock_gate  # noqa: E402
import rust_comments  # noqa: E402
from subsystem_spawn_gate import cfg_test_files, cfg_test_spans  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The crate whose diagnostics are the door; a workspace without it measured nothing.
DOOR = "wz-session-core"
#: The facade's crate name, as a dependency and as a path root.
FACADE = "log"

#: (path relative to the root) -> (how many places name the facade there, the reason).
ALLOWED: dict[str, tuple[int, str]] = {
    "crates/wz-session-core/src/diag.rs": (
        1,
        "the door: the re-export the diagnostic macros expand through, compiled only with "
        "the crate's `log` feature",
    ),
}

#: (crate) -> the reason it may name the facade as a dependency of its own.
LOG_DEPENDENCY: dict[str, str] = {
    "wz-session-core": (
        "the door's facade; not optional because the statechart runtime the session machines run "
        "on names it unconditionally, so an optional edge would leave out nothing (its "
        "Cargo.toml says so)"
    ),
}

#: (crate) -> why it calls the facade directly: a host's crate that no library without a logger
#: links. Each is checked to be a member, outside the cooperative C ABI's graph, and to call it.
EXEMPT: dict[str, str] = {
    "wz-admin": "the admin space of the tokio runtime's router and node",
    "wz-ap-demo": "the application processor demo binary, which installs its own logger",
    "wz-e2e-admin-probe": "an end-to-end test binary whose log lines are what its lane reads",
    "wz-e2e-declare-observer": "an end-to-end test binary whose log lines are what its lane reads",
    "wz-e2e-harness": "the harness of the end-to-end test binaries, which installs their logger",
    "wz-e2e-liveliness": "an end-to-end test binary whose log lines are what its lane reads",
    "wz-e2e-liveliness-token": "an end-to-end test binary whose log lines are what its lane reads",
    "wz-e2e-pubsub": "an end-to-end test binary whose log lines are what its lane reads",
    "wz-e2e-queryable": "an end-to-end test binary whose log lines are what its lane reads",
    "wz-e2e-zget": "an end-to-end test binary whose log lines are what its lane reads",
    "wz-host-net": "the host network layer of the tokio runtime",
    "wz-replay": "the capture replayer's live mode, a host tool",
    "wz-routing-graph": "the link-state graph of the tokio runtime's router",
    "wz-runtime-tokio": "the tokio runtime, whose hosts install a logger",
    "wz-storage": "the storage plane of the tokio runtime's router",
}

_ROOT = r"(?<![\w:])(?:::\s*)?" + FACADE
#: What names the facade, or hides that a later line does.
PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(_ROOT + r"\s*::\s*[A-Za-z_]\w*\s*!"),
    re.compile(r"\buse\s+(?:::\s*)?" + FACADE + r"\b"),
    re.compile(r"\bextern\s+crate\s+" + FACADE + r"\b"),
)
#: A module of the file's own named like the facade, which `log::` there names instead.
OWN_MODULE = re.compile(r"\bmod\s+" + FACADE + r"\s*[;{]")


class InputError(Exception):
    """An input this gate could not read. Reported as a FAIL, never a traceback."""


def members(meta: dict) -> dict[str, dict]:
    """`{crate: its package}` of the workspace members."""
    ids = set(meta.get("workspace_members", []))
    found = {pkg["name"]: pkg for pkg in meta.get("packages", []) if pkg.get("id") in ids}
    if DOOR not in found:
        raise InputError(f"{DOOR} is not a workspace member; nothing was measured")
    return found


def library_crates(tree: str) -> set[str]:
    """The packages a `cargo tree --prefix none` listing names."""
    return {line.split()[0] for line in tree.splitlines() if line.strip()}


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def places(root: Path, src: Path) -> list[tuple[str, int, str]]:
    """Every place production code under `src` names the facade or hides that it does:
    (path relative to `root`, line, the text)."""
    if not src.is_dir():
        raise InputError(f"no source directory at {src}")
    found: list[tuple[str, int, str]] = []
    files = sorted(src.rglob("*.rs"))
    test_only = cfg_test_files(files)
    for path in files:
        if path.resolve() in test_only:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        stripped = rust_comments.strip_comments(text, blank_literals=True)
        if OWN_MODULE.search(stripped):
            continue
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


def names_facade(pkg: dict) -> bool:
    """Whether `pkg` names the facade as a normal dependency, optional or not, on any target."""
    return any(
        dep.get("name") == FACADE and dep.get("kind") is None
        for dep in pkg.get("dependencies", [])
    )


def grade(
    root: Path,
    meta: dict,
    tree: str,
    allowed: dict[str, tuple[int, str]],
    exempt: dict[str, str],
    log_dependency: dict[str, str],
) -> tuple[list[str], int, int]:
    """The findings over `root`, `meta` and `tree` against the three lists, how many crates were
    graded and how many places were found in them."""
    findings: list[str] = []
    for what, entries in (
        ("allowed file", {k: v[1] for k, v in allowed.items()}),
        ("exempt crate", exempt),
        ("allowed dependency of", log_dependency),
    ):
        for name, reason in entries.items():
            if not reason.strip():
                findings.append(f"the {what} {name} states no reason")
    crates = members(meta)
    in_library = library_crates(tree)
    if DOOR not in in_library:
        raise InputError(f"the library's graph does not reach {DOOR}; nothing was measured")
    for name in sorted(exempt):
        if name not in crates:
            findings.append(f"the exempt crate {name} is not a workspace member")
            continue
        if name in in_library:
            findings.append(
                f"the exempt crate {name} is in the cooperative C ABI's graph, so a library "
                f"without a logger compiles its facade calls; call `wz_session_core::diag_warn!` "
                f"or `diag_debug!` and take it off EXEMPT"
            )
        src = Path(crates[name]["manifest_path"]).parent / "src"
        if not places(root, src):
            findings.append(f"the exempt crate {name} names the facade nowhere; take it off EXEMPT")
    graded = {name: pkg for name, pkg in crates.items() if name not in exempt}
    found: list[tuple[str, int, str]] = []
    for name, pkg in sorted(graded.items()):
        found += places(root, Path(pkg["manifest_path"]).parent / "src")
        if names_facade(pkg):
            if name not in log_dependency:
                findings.append(
                    f"{name} names `log` as a dependency of its own; its diagnostics go through "
                    f"{DOOR}'s (`diag`), whose `log` feature a build that wants records turns on"
                )
        elif name in log_dependency:
            findings.append(
                f"the allowed dependency of {name} is no longer named; take it off LOG_DEPENDENCY"
            )
    for name in sorted(log_dependency):
        if name not in graded:
            findings.append(f"the allowed dependency of {name} names no graded crate")
    counted: dict[str, int] = {}
    for rel, line, text in found:
        if rel in allowed:
            counted[rel] = counted.get(rel, 0) + 1
            continue
        findings.append(
            f"{rel}:{line} names the `log` facade ({text}); write `wz_session_core::diag_warn!` "
            f"or `diag_debug!`, which a build without `wz-session-core/log` compiles to nothing"
        )
    for rel, (want, _) in sorted(allowed.items()):
        have = counted.get(rel, 0)
        if have > want:
            findings.append(
                f"the allowed file {rel} names the facade in {have} places and the list allows "
                f"{want}: a call past the door"
            )
        elif have < want:
            findings.append(
                f"the allowed file {rel} names the facade in {have} places and the list allows "
                f"{want}; lower its count, or take it off ALLOWED at 0"
            )
    return findings, len(graded), len(found)


def check() -> int:
    try:
        meta = cargo_workspaces.metadata("crates")
        tree = host_lock_gate.library_tree(host_lock_gate.library_features(meta))
        findings, crates, found = grade(REPO_ROOT, meta, tree, ALLOWED, EXEMPT, LOG_DEPENDENCY)
    except (InputError, host_lock_gate.InputError, RuntimeError, OSError) as e:
        print(f"log-facade: FAIL -- cannot grade: {e}", file=sys.stderr)
        return 1
    if findings:
        print("log-facade: FAIL", file=sys.stderr)
        for line in findings:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print(
        f"log-facade: OK -- {crates} crate(s) graded, {found} place(s) naming the facade, each "
        f"counted in one of {len(ALLOWED)} allowed file(s); {len(EXEMPT)} host crate(s) exempt"
    )
    return 0


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _package(root: Path, name: str, deps: tuple[tuple[str, str | None], ...]) -> dict:
    return {
        "name": name,
        "id": f"{name} 0.1.0",
        "manifest_path": str(root / "crates" / name / "Cargo.toml"),
        "dependencies": [{"name": dep, "kind": kind} for dep, kind in deps],
    }


DIAG_SRC = (
    "#[cfg(feature = \"log\")]\npub use log as __log;\n"
    "#[cfg(test)]\nmod tests {\n    fn on() -> bool {\n"
    "        log::log_enabled!(log::Level::Debug)\n    }\n}\n"
)
SHELL = (
    "// log::warn!(\"a comment is prose\");\n"
    "pub fn quoted() -> &'static str {\n    \"log::warn!(x)\"\n}\n"
    "pub fn module() {\n    crate::log::emit();\n    wz_capi::event_log::emit!();\n}\n"
    "pub fn door() {\n    wz_session_core::diag_warn!(\"through the door\");\n}\n"
    "#[cfg(test)]\nmod tests {\n    use log::info;\n    fn t() {\n        log::warn!(\"a test\");\n"
    "    }\n}\n"
    "#[cfg(all(feature = \"x\", test))]\nmod more;\n"
)
TEST_FILE = "pub fn t() {\n    log::debug!(\"a test file\");\n}\n"
HOST_SRC = "pub fn host() {\n    log::info!(\"a host's line\");\n}\n"


def _fixture(
    root: Path,
    *,
    diag: str = DIAG_SRC,
    shell_extra: str = "",
    shell_deps: tuple[tuple[str, str | None], ...] = ((FACADE, "dev"),),
    door_deps: tuple[tuple[str, str | None], ...] = ((FACADE, None),),
    host: str = HOST_SRC,
    host_in_tree: bool = False,
    door_in_tree: bool = True,
):
    """A workspace under `root`, the metadata it reads as and the tree of the library: the door, a
    shell the library reaches and a host crate off the library's graph."""
    _write(root, f"crates/{DOOR}/src/lib.rs", "pub mod diag;\n")
    _write(root, f"crates/{DOOR}/src/diag.rs", diag)
    _write(root, "crates/shell/src/lib.rs", SHELL + shell_extra)
    _write(root, "crates/shell/src/more.rs", TEST_FILE)
    _write(root, "crates/host-only/src/lib.rs", host)
    packages = [
        _package(root, DOOR, door_deps),
        _package(root, "shell", shell_deps),
        _package(root, "host-only", ((FACADE, None),)),
    ]
    meta = {"packages": packages, "workspace_members": [p["id"] for p in packages]}
    tree = "\n".join(
        [f"{host_lock_gate.LIBRARY} v0.1.0 (/x)", "shell v0.1.0 (/x)"]
        + ([f"{DOOR} v0.1.0 (/x)"] if door_in_tree else [])
        + (["host-only v0.1.0 (/x)"] if host_in_tree else [])
    )
    return meta, tree


def selftest() -> int:
    """Drive every rule over a fixture workspace, in both directions."""
    failures: list[str] = []
    allowed = {f"crates/{DOOR}/src/diag.rs": (1, "the door")}
    exempt = {"host-only": "a host's"}
    log_dependency = {DOOR: "the door's facade"}
    shell = "crates/shell/src/lib.rs"
    at = SHELL.count("\n") + 1
    # (name, fixture arguments, a substring one finding carries, or None for no finding)
    rows: list[tuple[str, dict, str | None]] = [
        ("agrees", {}, None),
        ("a macro by its path", {"shell_extra": "fn f() { log::warn!(\"x\"); }\n"}, f"{shell}:{at} "),
        ("a leading root", {"shell_extra": "fn f() { ::log::debug!(\"x\"); }\n"}, "(::log::debug!)"),
        ("a spaced path", {"shell_extra": "fn f() { log :: info !(\"x\"); }\n"}, "(log :: info !)"),
        (
            "the facade's own check",
            {"shell_extra": "fn f() -> bool { log::log_enabled!(log::Level::Warn) }\n"},
            "(log::log_enabled!)",
        ),
        ("an import", {"shell_extra": "use log::warn;\n"}, "(use log)"),
        ("an import tree", {"shell_extra": "use log::{debug, warn};\n"}, "(use log)"),
        ("a rename", {"shell_extra": "use log as l;\n"}, "(use log)"),
        ("a rooted import", {"shell_extra": "use ::log::warn;\n"}, "(use ::log)"),
        ("the crate", {"shell_extra": "#[macro_use]\nextern crate log;\n"}, "(extern crate log)"),
        (
            "a module of its own",
            {"shell_extra": "mod log {\n    pub fn f() {}\n}\npub use log::f;\nfn g() { log::f(); }\n"},
            None,
        ),
        ("an import of a longer name", {"shell_extra": "use logos::Lexer;\n"}, None),
        (
            "one more in the door",
            {"diag": DIAG_SRC + "pub fn d() { log::warn!(\"past\"); }\n"},
            "in 2 places and the list allows 1: a call past the door",
        ),
        (
            "the door no longer names it",
            {"diag": "pub fn d() {}\n"},
            "in 0 places and the list allows 1;",
        ),
        (
            "a dependency of its own",
            {"shell_deps": ((FACADE, None),)},
            "shell names `log` as a dependency of its own",
        ),
        ("a build dependency", {"shell_deps": ((FACADE, "build"),)}, None),
        (
            "the door no longer depends on it",
            {"door_deps": ()},
            "the allowed dependency of wz-session-core is no longer named",
        ),
        (
            "an exempt crate the library links",
            {"host_in_tree": True},
            "the exempt crate host-only is in the cooperative C ABI's graph",
        ),
        (
            "an exempt crate that calls nothing",
            {"host": "pub fn host() {}\n"},
            "the exempt crate host-only names the facade nowhere",
        ),
    ]
    for name, kwargs, want in rows:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            meta, tree = _fixture(root, **kwargs)
            try:
                findings, crates, found = grade(root, meta, tree, allowed, exempt, log_dependency)
            except InputError as e:
                failures.append(f"{name}: cannot grade: {e}")
                continue
        if want is None:
            if findings:
                failures.append(f"{name}: want no finding, got {findings}")
            if (crates, found) != (2, 1):
                failures.append(
                    f"{name}: want 2 crates and the door's 1 place, got {crates} and {found}"
                )
        elif len(findings) != 1 or want not in findings[0]:
            failures.append(f"{name}: want one finding carrying {want!r}, got {findings}")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        meta, tree = _fixture(root, door_in_tree=False)
        try:
            grade(root, meta, tree, allowed, exempt, log_dependency)
            failures.append("a graph without the door is graded; it measured nothing")
        except InputError:
            pass
        meta, tree = _fixture(root)
        findings, _, _ = grade(
            root, meta, tree, allowed, {**exempt, "gone": "a crate"}, log_dependency
        )
        if not any("the exempt crate gone is not a workspace member" in f for f in findings):
            failures.append(f"an exempt crate that is no member is refused, got {findings}")
        findings, _, _ = grade(root, meta, tree, allowed, {"host-only": " "}, log_dependency)
        if not any("states no reason" in f for f in findings):
            failures.append(f"an exempt crate with no reason is refused, got {findings}")

    for rel, (count, reason) in ALLOWED.items():
        if not (REPO_ROOT / rel).is_file():
            failures.append(f"ALLOWED names {rel}, which is not a file")
        if count < 1:
            failures.append(f"ALLOWED entry {rel} allows no place; take it off the list")
        if not reason.strip():
            failures.append(f"ALLOWED entry {rel} states no reason")
    for name, reason in {**EXEMPT, **LOG_DEPENDENCY}.items():
        if not (REPO_ROOT / "crates" / name / "Cargo.toml").is_file():
            failures.append(f"{name} is listed and has no crates/{name}/Cargo.toml")
        if not reason.strip():
            failures.append(f"{name} is listed with no reason")

    if failures:
        for line in failures:
            print(f"log-facade: SELFTEST FAIL -- {line}", file=sys.stderr)
        return 1
    print(f"log-facade: selftest OK -- {len(rows)} fixture rows and the refused inputs")
    return 0


def main(argv: list[str]) -> int:
    modes = {"--check": check, "--selftest": selftest}
    if len(argv) != 2 or argv[1] not in modes:
        print(
            "usage: log_facade_gate.py --check | --selftest "
            "(a mode is required; there is no default)",
            file=sys.stderr,
        )
        return 2
    return modes[argv[1]]()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
