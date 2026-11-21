#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4582 (no register item) -- a crate built on the cooperative runtime enters a critical section
only through the runtime's door.

The round cited is main's at the hosted runs the defect below was read from; no register item
named it.

## Why

`wz-runtime-coop`'s critical sections are one function, `cs::with`
(crates/wz-runtime-coop/src/cs.rs), and what a section IS depends on the build: the runtime's
own lock of the process on a host (`host-lock`, which a host library selects), nothing on an
image that states a single context (`single-context`), and otherwise the `critical-section`
implementation an MCU image links. A host build of a library over the runtime therefore links
no `critical-section` implementation.

A crate that calls `critical_section::with` itself steps around that choice. On an MCU it still
works, which is why nothing there notices. On a host it leaves a reference to
`_critical_section_1_0_acquire` and `_critical_section_1_0_release` that nothing defines. A Linux
link drops the reference with the unreached code that holds it, so every Linux row is green; the
Windows linker refuses an unresolved name in any object it takes, reached or not, and the
cooperative library did not link there. And if such a section is ever reached on Linux, the
library resolves the name at load time from whatever else the process links, or fails to load.

This gate makes the rule a Linux verdict: the crates on the runtime name `critical-section`'s own
section in one file, the door.

## The population

Every workspace member with a NORMAL dependency on `wz-runtime-coop` (on any target), and the
runtime itself, as `cargo metadata` of the `crates/` workspace reads them: their `src/**.rs`,
minus every file and item that exists only in a test build (`subsystem_spawn_gate`'s reader, so
the gates agree on what test code is). A test links critical-section's std implementation and is
free to call it. A crate that depends on the runtime only for its tests is not in the population;
neither is an MCU crate that does not build on the runtime and links an image's implementation
for its own cells.

A population without the runtime is a FAIL: nothing was measured.

## What is refused

Outside a comment and a string literal, anywhere but in `ALLOWED`:

  * a call of `critical_section::with`, `critical_section::acquire` or `critical_section::release`;
  * a use tree of `critical_section` that imports one of the three, after which the call names no
    crate;
  * a rename of the crate (`critical_section as ..`, `self as ..`) and a glob import of it, after
    which this gate cannot see a call.

A file in `ALLOWED` that no longer names one of them is refused too, so the list holds the door
and nothing that has left it.

What this cannot see, stated rather than implied: a manifest that renames the package
(`package = "critical-section"` under another key) and a call a macro of another crate expands
into a crate of the population.

Usage:
    python3 scripts/lib/coop_critical_section_gate.py --check
    python3 scripts/lib/coop_critical_section_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cargo_workspaces  # noqa: E402  -- after the path insert that finds it
import rust_comments  # noqa: E402
from subsystem_spawn_gate import cfg_test_files, cfg_test_spans  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The runtime whose door the population takes its sections through.
RUNTIME = "wz-runtime-coop"

#: (path relative to the root) -> the reason the file may enter `critical-section`'s own section.
ALLOWED: dict[str, str] = {
    "crates/wz-runtime-coop/src/cs.rs": (
        "the door: the image's implementation, in a build with neither `host-lock` nor "
        "`single-context`"
    ),
}

#: What enters `critical-section`'s own section, or hides that a later line does.
PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<![\w])critical_section\s*::\s*(?:with|acquire|release)\b"),
    re.compile(r"(?<![\w])critical_section\s*::\s*\{[^}]*\b(?:with|acquire|release)\b[^}]*\}"),
    re.compile(r"(?<![\w])critical_section\s+as\s+[A-Za-z_]\w*"),
    re.compile(r"(?<![\w])critical_section\s*::\s*\{[^}]*\bself\s+as\s+[A-Za-z_]\w*[^}]*\}"),
    re.compile(r"(?<![\w])critical_section\s*::\s*\*"),
)


class InputError(Exception):
    """An input this gate could not read. Reported as a FAIL, never a traceback."""


def population(meta: dict) -> dict[str, Path]:
    """`{crate: its src directory}` of the members on the runtime, the runtime among them."""
    ids = set(meta.get("workspace_members", []))
    crates: dict[str, Path] = {}
    for pkg in meta.get("packages", []):
        if pkg.get("id") not in ids:
            continue
        on_runtime = pkg.get("name") == RUNTIME or any(
            dep.get("name") == RUNTIME and not dep.get("kind") for dep in pkg.get("dependencies", [])
        )
        if on_runtime:
            crates[pkg["name"]] = Path(pkg["manifest_path"]).parent / "src"
    if RUNTIME not in crates:
        raise InputError(f"{RUNTIME} is not a workspace member; nothing was measured")
    return crates


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def sections(root: Path, crates: dict[str, Path]) -> list[tuple[str, int, str]]:
    """Every place production code of `crates` names `critical-section`'s own section:
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
            for pattern in PATTERNS:
                for m in pattern.finditer(stripped):
                    if any(a <= m.start() <= b for a, b in skip):
                        continue
                    line = stripped.count("\n", 0, m.start()) + 1
                    found.append((rel, line, " ".join(m.group(0).split())))
    return sorted(set(found))


def grade(root: Path, meta: dict, allowed: dict[str, str]) -> tuple[list[str], int, int]:
    """The findings over `root` and `meta` against `allowed`, the population's size and how many
    places were found."""
    findings: list[str] = []
    for rel, reason in allowed.items():
        if not reason.strip():
            findings.append(f"the allowed file {rel} states no reason")
    crates = population(meta)
    found = sections(root, crates)
    used: set[str] = set()
    for rel, line, text in found:
        if rel in allowed:
            used.add(rel)
            continue
        findings.append(
            f"{rel}:{line} enters `critical-section`'s own section past the runtime's door "
            f"({text}); call `wz_runtime_coop::cs::with`, which is the host's lock in a host "
            f"build and the image's implementation on an MCU, and name no `critical-section` "
            f"dependency in a crate that does not implement it"
        )
    for rel in sorted(set(allowed) - used):
        findings.append(
            f"the allowed file {rel} enters no critical section any longer; take it off ALLOWED"
        )
    return findings, len(crates), len(found)


def check() -> int:
    try:
        meta = cargo_workspaces.metadata("crates")
        findings, crates, found = grade(REPO_ROOT, meta, ALLOWED)
    except (InputError, RuntimeError, OSError) as e:
        print(f"coop-critical-section: FAIL -- cannot grade: {e}", file=sys.stderr)
        return 1
    if findings:
        print("coop-critical-section: FAIL", file=sys.stderr)
        for line in findings:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print(
        f"coop-critical-section: OK -- {crates} crate(s) on the cooperative runtime, "
        f"{found} critical-section entry point(s), each in one of {len(ALLOWED)} allowed file(s)"
    )
    return 0


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _dep(name: str, kind: str | None = None, target: str | None = None) -> dict:
    return {"name": name, "kind": kind, "target": target}


def _package(root: Path, name: str, deps: tuple[dict, ...]) -> dict:
    return {
        "name": name,
        "id": f"{name} 0.1.0",
        "manifest_path": str(root / "crates" / name / "Cargo.toml"),
        "dependencies": list(deps),
    }


DOOR = "pub fn with<R>(f: impl FnOnce() -> R) -> R {\n    critical_section::with(|_| f())\n}\n"
SHELL = (
    "pub fn through_the_door() {\n    wz_runtime_coop::cs::with(|_| ());\n}\n"
    "// critical_section::with(|_| ()) in a comment is prose.\n"
    "pub fn quoted() -> &'static str {\n    \"critical_section::with\"\n}\n"
    "pub use critical_section::Mutex;\n"
    "#[cfg(test)]\nmod tests {\n    fn t() {\n        critical_section::with(|_| ());\n    }\n}\n"
    "#[cfg(all(test, feature = \"x\"))]\nmod more;\n"
)
CALL = "pub fn bad() {\n    critical_section::with(|_| ());\n}\n"


def _fixture(
    root: Path,
    *,
    door: str = DOOR,
    shell_extra: str = "",
    shell_dep: dict | None = None,
    runtime: bool = True,
) -> dict:
    """A workspace under `root` and the metadata it reads as: the runtime and its door, a shell on
    the runtime, an image crate off it and a crate that takes the runtime for its tests only."""
    _write(root, f"crates/{RUNTIME}/src/lib.rs", "pub mod cs;\n")
    _write(root, f"crates/{RUNTIME}/src/cs.rs", door)
    _write(root, "crates/shell/src/lib.rs", SHELL + shell_extra)
    _write(root, "crates/shell/src/more.rs", "fn t() {\n    critical_section::with(|_| ());\n}\n")
    _write(root, "crates/image/src/lib.rs", CALL)
    _write(root, "crates/tested/src/lib.rs", CALL)
    packages = [
        _package(root, "shell", (shell_dep if shell_dep is not None else _dep(RUNTIME),)),
        _package(root, "image", (_dep("critical-section"),)),
        _package(root, "tested", (_dep(RUNTIME, kind="dev"),)),
    ]
    if runtime:
        packages.append(_package(root, RUNTIME, (_dep("critical-section"),)))
    return {"packages": packages, "workspace_members": [p["id"] for p in packages]}


def selftest() -> int:
    """Drive every rule over a fixture workspace, in both directions."""
    failures: list[str] = []
    allowed = {f"crates/{RUNTIME}/src/cs.rs": "the door"}
    call_line = SHELL.count("\n") + 2
    # (name, fixture arguments, a substring one finding carries, or None for no finding)
    rows: list[tuple[str, dict, str | None]] = [
        ("agrees", {}, None),
        ("a call past the door", {"shell_extra": CALL}, f"crates/shell/src/lib.rs:{call_line} "),
        (
            "a section entered by hand",
            {"shell_extra": "pub fn raw() {\n    let _ = unsafe { critical_section::acquire() };\n}\n"},
            "(critical_section::acquire)",
        ),
        (
            "an import of the call",
            {"shell_extra": "use critical_section::{with, CriticalSection};\n"},
            "(critical_section::{with, CriticalSection})",
        ),
        (
            "a rename",
            {"shell_extra": "use critical_section as sections;\n"},
            "(critical_section as sections)",
        ),
        (
            "a rename in a use tree",
            {"shell_extra": "use critical_section::{self as sections, Mutex as M};\n"},
            "(critical_section::{self as sections, Mutex as M})",
        ),
        ("a glob", {"shell_extra": "use critical_section::*;\n"}, "(critical_section::*)"),
        (
            "a dependency on one target only",
            {"shell_extra": CALL, "shell_dep": _dep(RUNTIME, target="cfg(windows)")},
            f"crates/shell/src/lib.rs:{call_line} ",
        ),
        (
            "the door no longer enters",
            {"door": "pub fn with<R>(f: impl FnOnce() -> R) -> R {\n    f()\n}\n"},
            "enters no critical section any longer",
        ),
    ]
    for name, kwargs, want in rows:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            meta = _fixture(root, **kwargs)
            try:
                findings, crates, found = grade(root, meta, allowed)
            except InputError as e:
                failures.append(f"{name}: cannot grade: {e}")
                continue
        if want is None:
            if findings:
                failures.append(f"{name}: want no finding, got {findings}")
            if (crates, found) != (2, 1):
                failures.append(f"{name}: want 2 crates and the door's 1 entry, got {crates} and {found}")
        elif len(findings) != 1 or want not in findings[0]:
            failures.append(f"{name}: want one finding carrying {want!r}, got {findings}")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        meta = _fixture(root, runtime=False)
        try:
            grade(root, meta, allowed)
            failures.append("a workspace without the runtime is graded; it measured nothing")
        except InputError:
            pass
        meta = _fixture(root)
        findings, _, _ = grade(root, meta, {**allowed, "crates/shell/src/lib.rs": " "})
        if not any("states no reason" in f for f in findings):
            failures.append(f"an allowed file with no reason is refused, got {findings}")

    for rel, reason in ALLOWED.items():
        if not (REPO_ROOT / rel).is_file():
            failures.append(f"ALLOWED names {rel}, which is not a file")
        if not reason.strip():
            failures.append(f"ALLOWED entry {rel} states no reason")

    if failures:
        for line in failures:
            print(f"coop-critical-section: SELFTEST FAIL -- {line}", file=sys.stderr)
        return 1
    print(f"coop-critical-section: selftest OK -- {len(rows)} fixture rows and the refused inputs")
    return 0


def main(argv: list[str]) -> int:
    modes = {"--check": check, "--selftest": selftest}
    if len(argv) != 2 or argv[1] not in modes:
        print(
            "usage: coop_critical_section_gate.py --check | --selftest "
            "(a mode is required; there is no default)",
            file=sys.stderr,
        )
        return 2
    return modes[argv[1]]()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
