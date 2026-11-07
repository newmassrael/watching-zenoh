#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""A product path of this checkout is named through the artifact root.

`scripts/lib/artifact-root.sh` states the rule: a product of the tree path
`<rel>` is at `<checkout>/<rel>` when `WZ_ARTIFACT_ROOT` is unset and at
`$WZ_ARTIFACT_ROOT/<rel>` when it is set, and with a root set nothing is written
into the checkout. A consumer relies on that by mounting the checkout read-only.

The rule holds only while every writer and every reader asks it. One script
that still spells `"$ROOT/target/x"`, or one test that still joins
`project_root().join("target/x")`, writes into a read-only mount (the lane dies
with EROFS) or reads a directory nobody wrote (the lane skips, or grades a stale
product). Neither shows up while the root is unset, which is how every lane runs
by default -- so the drift would be invisible until a consumer hit it. This lint
makes it visible at the change.

## What is graded

Tracked files of three languages, comment lines excluded:

* shell (`scripts/**/*.sh`, the cargo shim): a product path rooted at the
  checkout through a variable (`$ROOT/target`, `$repo_root/crates/target`,
  `$PWD/deploy/<x>/target-…`), or a RELATIVE product path word (`target/…`,
  `crates/target/…`, `deploy/<x>/target…`). The spelling the rule wants is
  `$WZ_ARTIFACTS/<rel>` (or `wz_artifact_dir <path>`), which neither pattern
  matches.
* Python (`scripts/**/*.py`): a checkout-rooted join (`ROOT / "target"`,
  `CRATES / "target" / …`, `REPO / "crates/target/…"`) or a `Path("target/…")`
  literal. The spelling the rule wants is `artifact("<rel>")`
  (`scripts/lib/artifact_root.py`).
* Rust (`crates/**/*.rs`): a `.join("target…")` / `.join("crates/target…")` /
  `.join("../../target…")` / `.push("target")` on a line that does not go
  through the artifact helpers (`wz_codegen_build::artifact`, `artifact_dir`,
  or a crate's own `artifact…` wrapper of them).

A relative name that is only a NAME (`"target/zenohd"` as an oracle key handed
to `artifact()` or to the store) is not a path and is not matched: the patterns
need a checkout anchor (a variable, `Path(`, `.join(`) or a shell word.

## Exemptions

`EXEMPT` lists files whose job is the checkout's OWN build directory -- the
maintenance tools a developer runs on a checkout, never a lane -- with the
reason. An exemption that no longer matches anything is itself a failure, so the
list cannot outlive what it excuses.

The population floor is a minimum, not a budget: a lint whose population fell
to zero would report green while reading nothing.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: `(file, line substring or None for the whole file, reason)`. Each entry must
#: still excuse at least one finding, or it is reported as stale.
EXEMPT: list[tuple[str, str | None, str]] = [
    (
        "scripts/sweep-target.sh",
        None,
        "reaps the checkout's own crates/target with cargo-sweep, whose stamp lives in the "
        "project directory; a developer's maintenance tool, never a lane",
    ),
    (
        "crates/wz-codegen-build/tests/provenance.rs",
        None,
        "builds a fake SCE workspace in a temporary directory, whose target/ is the fixture",
    ),
    (
        "scripts/run-ci.sh",
        "wz_packet_socket-[a-f0-9]+",
        "parses cargo's own output for the test executable's name by its suffix, which is the "
        "same under a root; the next line puts the root in front of it",
    ),
    (
        "scripts/lib/abi_stamp_gate.py",
        "profile_of(",
        "a selftest input: profile_of() parses a path's SHAPE, nothing is read",
    ),
    (
        "scripts/lib/capi_c_abi_pin.py",
        "profile_of(",
        "a selftest input: profile_of() parses a path's SHAPE, nothing is read",
    ),
]


def _excuse(rel: str, line: str) -> int | None:
    """The index of the exemption that excuses this finding, if one does."""
    for i, (file, part, _why) in enumerate(EXEMPT):
        if file == rel and (part is None or part in line):
            return i
    return None

#: The fewest files the population may hold before the lint refuses to grade.
POPULATION_FLOOR = 400

_ANCHOR_VARS = r"(?:ROOT|root|repo_root|REPO_ROOT|repo|PWD)"
_PRODUCT = r"(?:crates/|deploy/[A-Za-z0-9._-]+/)?target(?:/|-[A-Za-z0-9]|\b)"
SH_VAR_RE = re.compile(r"\$\{?" + _ANCHOR_VARS + r"\}?/" + _PRODUCT)
# A bare `target` needs a `/` after it (`target-libdir` is a rustc word); a
# prefixed one may also take a suffix (`crates/target-ab-x`,
# `deploy/<x>/target-loopback`). `-f target/<chip>.cfg` is openocd's own script
# search path, not a path of this checkout.
SH_REL_RE = re.compile(
    r"""(?:^|(?<!-f)[\s"'=(:]|:-)(?:\./)?"""
    r"""(?:(?:crates/|deploy/[A-Za-z0-9._-]+/)target(?:/|-[A-Za-z0-9])|target/)"""
)
# The module constants that name the checkout. A lowercase `root` is a function's
# argument -- a selftest's temporary tree, or a root a caller chose -- and is the
# caller's to place.
PY_JOIN_RE = re.compile(
    r"""\b(?:ROOT|REPO|REPO_ROOT|CRATES|WORKSPACE)\s*/\s*["'](?:crates/)?target\b"""
)
PY_PATH_RE = re.compile(r"""Path\(\s*["'](?:\./)?(?:crates/)?target\b""")
RS_RE = re.compile(r"""\.(?:join|push)\(\s*"(?:\.\./)*(?:crates/)?target(?:/|")""")


def _code_lines(text: str, comment: str) -> list[tuple[int, str]]:
    """Lines that are not whole-line comments, numbered from 1."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith(comment):
            continue
        if comment == "//" and (stripped.startswith("*") or stripped.startswith("/*")):
            continue
        out.append((n, line))
    return out


def findings_in(rel: str, text: str) -> list[str]:
    """Every line of one file that names a product path past the rule."""
    found: list[str] = []
    if rel.endswith(".sh") or rel == "scripts/lib/artifact-root-bin/cargo":
        for n, line in _code_lines(text, "#"):
            if SH_VAR_RE.search(line):
                found.append(f"{rel}:{n}: {line.strip()}")
            elif SH_REL_RE.search(line) and "wz_artifact_dir" not in line:
                found.append(f"{rel}:{n}: {line.strip()}")
    elif rel.endswith(".py"):
        for n, line in _code_lines(text, "#"):
            if PY_JOIN_RE.search(line) or PY_PATH_RE.search(line):
                found.append(f"{rel}:{n}: {line.strip()}")
    elif rel.endswith(".rs"):
        for n, line in _code_lines(text, "//"):
            if RS_RE.search(line) and "artifact" not in line:
                found.append(f"{rel}:{n}: {line.strip()}")
    return found


def population(root: pathlib.Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "scripts", "crates"],
        capture_output=True,
        check=True,
    ).stdout.decode()
    files = []
    for rel in out.split("\0"):
        if not rel or rel.startswith("crates/target"):
            continue
        if rel.endswith((".sh", ".py", ".rs")) or rel == "scripts/lib/artifact-root-bin/cargo":
            files.append(rel)
    return files


def run(root: pathlib.Path, files: list[str], floor: int = POPULATION_FLOOR) -> int:
    if len(files) < floor:
        print(
            f"artifact-root-lint: FAIL -- {len(files)} file(s) read, under the floor of {floor}; "
            "a lint that read nothing must not pass"
        )
        return 1
    violations: list[str] = []
    used: set[int] = set()
    for rel in files:
        try:
            text = (root / rel).read_text(errors="replace")
        except OSError:
            continue
        for finding in findings_in(rel, text):
            excused = _excuse(rel, finding)
            if excused is None:
                violations.append(finding)
            else:
                used.add(excused)
    stale = [
        f"{file}{'' if part is None else f' ({part!r})'}"
        for i, (file, part, _why) in enumerate(EXEMPT)
        if i not in used
    ]
    missing: list[str] = []
    if violations or stale:
        for v in violations:
            print(f"  artifact-root-lint: {v}")
        if violations:
            print(
                f"artifact-root-lint: FAIL -- {len(violations)} product path(s) named past the "
                "artifact root. Spell them `$WZ_ARTIFACTS/<rel>` or `wz_artifact_dir` (shell), "
                "`artifact(\"<rel>\")` (Python, scripts/lib/artifact_root.py), "
                "`wz_codegen_build::artifact` (Rust); see scripts/lib/artifact-root.sh"
            )
        for rel in stale + missing:
            print(f"artifact-root-lint: FAIL -- the exemption of {rel} excuses nothing; remove it")
        return 1
    print(
        f"  artifact-root-lint: {len(files)} file(s) read, 0 product path past the artifact root, "
        f"{len(EXEMPT)} exemption(s) each still excusing a use"
    )
    return 0


def selftest() -> int:
    bad = {
        "a.sh": 'X="$ROOT/target/zenohd"\n',
        "b.sh": 'if [[ -x target/zenoh-pico-cli/z_put ]]; then :; fi\n',
        "c.sh": 'L="${RUNCI_LOG_DIR:-crates/target/run-ci-logs}"\n',
        "d.sh": 'CARGO_TARGET_DIR="$repo_root/deploy/mcu-x/target-two" cargo build\n',
        "e.py": 'P = ROOT / "target" / "zenohd"\n',
        "f.py": 'C = pathlib.Path("crates/target/release/x.so")\n',
        "g.rs": 'let p = project_root().join("target/zenohd/zenohd");\n',
        "h.rs": 'let p = dir.join("../../target/zenohd/zenohd");\n',
    }
    good = {
        "a.sh": 'X="$WZ_ARTIFACTS/target/zenohd"\n# Y="$ROOT/target/zenohd"\n',
        "b.sh": 'cargo build --target-dir "$WZ_ARTIFACTS/target/x" --target thumbv7m\n',
        "c.sh": 'git status --porcelain -- . ":(exclude)target"\nfind . -not -path "*/target/*"\n',
        "d.sh": 'L="$(wz_artifact_dir crates/target/run-ci-logs)"\n',
        "e.py": 'P = artifact("target/zenohd")\nif "target" in rel.parts: pass\nK = "target/zenohd"\n',
        "g.rs": 'let p = artifact("target/zenohd/zenohd");\nlet q = artifact_dir(w).join("target/release");\n',
        "h.rs": '// let p = project_root().join("target/zenohd");\n',
    }
    failures = 0

    def expect(ok: bool, what: str) -> None:
        nonlocal failures
        if not ok:
            failures += 1
            print(f"artifact-root-lint selftest FAIL: {what}")

    for rel, text in bad.items():
        expect(bool(findings_in(rel, text)), f"{rel} {text.strip()!r} was not caught")
    for rel, text in good.items():
        expect(not findings_in(rel, text), f"{rel} {findings_in(rel, text)} was caught")

    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        (base / "ok.sh").write_text(good["a.sh"])
        expect(run(base, ["ok.sh"], floor=2) == 1, "a population under the floor passed")
        saved = list(EXEMPT)
        try:
            EXEMPT.clear()
            EXEMPT.append(("ok.sh", None, "a test exemption"))
            expect(run(base, ["ok.sh"], floor=1) == 1, "an exemption that excuses nothing passed")
            EXEMPT.clear()
            (base / "bad.sh").write_text(bad["a.sh"])
            expect(run(base, ["ok.sh", "bad.sh"], floor=1) == 1, "a violation passed")
            expect(run(base, ["ok.sh"], floor=1) == 0, "a clean population failed")
            EXEMPT.append(("bad.sh", "$ROOT/target", "a line-scoped test exemption"))
            expect(run(base, ["ok.sh", "bad.sh"], floor=1) == 0, "a line exemption did not excuse")
            EXEMPT[-1] = ("bad.sh", "something else", "a line exemption for another line")
            expect(run(base, ["ok.sh", "bad.sh"], floor=1) == 1, "a line exemption excused all")
        finally:
            EXEMPT.clear()
            EXEMPT.extend(saved)
    if failures:
        return 1
    print("artifact-root-lint selftest: ok")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    if sys.argv[1:]:
        print("usage: artifact_root_lint.py [--selftest]", file=sys.stderr)
        return 2
    return run(ROOT, population(ROOT))


if __name__ == "__main__":
    sys.exit(main())
