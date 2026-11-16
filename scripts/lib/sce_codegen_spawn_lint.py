#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y756 (N58, N62) -- sce-codegen is spawned through its door, and nowhere else.

`sce-codegen` finds its workspace, its Jinja2 templates and its XSD schemas by
looking around the machine it runs on when it is not told. A spawn site that
names one of the three and not the others inherits whatever the machine
answers, and that answer is wrong only on a machine other than the one the
site was written on, so the site passes where it is reviewed. Four sites were
found that way one at a time, two of which already passed the workspace root.

So there is ONE door per language, and it names all three:

* Rust: `SceCodegen` in `crates/wz-codegen-build/src/spawn.rs`. The crate is
  the door as a whole; its tests build fake binaries and workspaces.
* shell: `sce_codegen_spawn()` in `scripts/lib/sce-codegen-oracle.sh`.

The XSD validation is the quiet half (N62). When `sce-codegen` cannot validate
it warns and goes on to emit with exit status 0. Both doors refuse that run,
before the spawn when the schema is not where it is named, and after it when
the generator says validation did not run. The text they look for is held here
to be the same in both doors and, where the SCE checkout is present, to still
be what the generator prints: a door that looks for words the generator no
longer says is a check that stopped running.

## What is a direct spawn

Tracked files outside the doors, comment lines excluded:

* Rust: a string literal that is the binary's path (`"sce-codegen"`,
  `".../release/sce-codegen"`, the `"sce-codegen{}"` a suffix is formatted
  into), a call of the crate-private locator, a `Command::new` over the door's
  `binary()`, or one of the three locations spelled as a literal
  (`"--workspace-root"`, the two variables) -- naming one of those by hand is
  configuring a spawn by hand.
* shell, workflow and hook files: the binary (by name, or through a variable
  whose name carries `SCE_CODEGEN`) followed by one of its subcommands or a
  flag, or one of the three locations on a code line.
* Python: a string token that is the binary's path followed by a subcommand
  token (an argv), or a string token that is exactly one of the three
  locations.

## Exemptions

`EXEMPT` names a file and the reason; one that no longer excuses anything is a
failure, so the list cannot outlive what it excuses. The population floor is a
minimum: a lint that read nothing must not pass.
"""

from __future__ import annotations

import io
import pathlib
import re
import subprocess
import sys
import tempfile
import tokenize

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Paths whose spawns are the door, relative to the checkout. A path ending in
#: `/` is a directory prefix.
DOORS = ("crates/wz-codegen-build/", "scripts/lib/sce-codegen-oracle.sh")
RUST_DOOR = "crates/wz-codegen-build/src/spawn.rs"
SHELL_DOOR = "scripts/lib/sce-codegen-oracle.sh"
#: Where SCE prints the warning the doors look for.
SCE_WARNING_SOURCE = "vendor/sce/sce-build/src/forge/xsd_validator.rs"

#: `(file, line substring or None for the whole file, reason)`.
EXEMPT: list[tuple[str, str | None, str]] = [
    (
        "scripts/lib/sce_codegen_spawn_lint.py",
        None,
        "this lint's own patterns and selftest fixtures spell what it catches",
    ),
]

#: The fewest files the population may hold before the lint refuses to grade.
POPULATION_FLOOR = 1000

LOCATIONS = ("--workspace-root", "SCE_TEMPLATE_DIR", "SCE_SCHEMAS_DIR")
SUBCOMMANDS = ("generate", "check", "orchestrate", "generate-integration", "read-metadata")

_BIN_PATH = r"(?:[^\"'\s]*/)?sce-codegen(?:\{\})?(?:\.exe)?"
RS_BINARY_RE = re.compile(r'"' + _BIN_PATH + r'"')
RS_LOCATOR_RE = re.compile(r"\blocate_sce_codegen\s*\(")
RS_ESCAPE_RE = re.compile(r"Command::new\(\s*&?[\w.]*\.binary\(\)\s*\)")
RS_LOCATION_RE = re.compile(r'"(?:' + "|".join(re.escape(x) for x in LOCATIONS) + r')"')

SH_INVOKE_RE = re.compile(
    r"(?:sce-codegen|\$\{?[A-Za-z_]*SCE_CODEGEN[A-Za-z0-9_]*\}?)[\"']?\s+"
    r"(?:(?:" + "|".join(SUBCOMMANDS) + r")\b|--[a-z])"
)
SH_LOCATION_RE = re.compile("|".join(re.escape(x) for x in LOCATIONS))

PY_BINARY_RE = re.compile(r"^" + _BIN_PATH + r"$")
PY_ARG_RE = re.compile(r"^(?:(?:" + "|".join(SUBCOMMANDS) + r")|--[a-z][\w-]*)$")

RUST_MARKER_RE = re.compile(r'pub const XSD_NOT_VALIDATED: &str = "([^"]+)";')
SHELL_MARKER_RE = re.compile(r'^WZ_SCE_XSD_NOT_VALIDATED="([^"]+)"$', re.M)


def is_door(rel: str) -> bool:
    return any(rel.startswith(d) if d.endswith("/") else rel == d for d in DOORS)


def is_shell(rel: str) -> bool:
    return rel.endswith((".sh", ".yml", ".yaml")) or rel.startswith(".githooks/")


def _rust_code_lines(text: str) -> list[tuple[int, str]]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.lstrip()
        if s.startswith(("//", "/*", "*")):
            continue
        out.append((n, line))
    return out


def _shell_code_lines(text: str) -> list[tuple[int, str]]:
    """Code lines with backslash continuations joined, numbered by their first
    line, so an argument on the next line is read as part of its command."""
    out: list[tuple[int, str]] = []
    pending: tuple[int, str] | None = None
    for n, line in enumerate(text.splitlines(), 1):
        if pending is None:
            if line.lstrip().startswith("#"):
                continue
            pending = (n, line)
        else:
            pending = (pending[0], pending[1] + " " + line.strip())
        if pending[1].endswith("\\"):
            pending = (pending[0], pending[1][:-1])
            continue
        out.append(pending)
        pending = None
    if pending is not None:
        out.append(pending)
    return out


def _python_strings(text: str) -> list[tuple[int, str]]:
    """Every plain string token's value, with its line. A file that does not
    tokenize yields nothing here and is not this lint's to diagnose."""
    out = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type != tokenize.STRING:
                continue
            body = tok.string.lstrip("rbufRBUF")
            for q in ('"""', "'''", '"', "'"):
                if body.startswith(q) and body.endswith(q) and len(body) >= 2 * len(q):
                    out.append((tok.start[0], body[len(q) : -len(q)]))
                    break
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return []
    return out


def findings_in(rel: str, text: str) -> list[str]:
    """Every place in one file that spawns sce-codegen past the doors."""
    found: list[str] = []
    if rel.endswith(".rs"):
        for n, line in _rust_code_lines(text):
            if (
                RS_BINARY_RE.search(line)
                or RS_LOCATOR_RE.search(line)
                or RS_ESCAPE_RE.search(line)
                or RS_LOCATION_RE.search(line)
            ):
                found.append(f"{rel}:{n}: {line.strip()}")
    elif rel.endswith(".py"):
        strings = _python_strings(text)
        for i, (n, value) in enumerate(strings):
            argv = (
                PY_BINARY_RE.match(value)
                and i + 1 < len(strings)
                and PY_ARG_RE.match(strings[i + 1][1])
            )
            if argv or value in LOCATIONS:
                found.append(f"{rel}:{n}: {value!r}")
    elif is_shell(rel):
        for n, line in _shell_code_lines(text):
            if SH_INVOKE_RE.search(line) or SH_LOCATION_RE.search(line):
                found.append(f"{rel}:{n}: {line.strip()}")
    return found


def _excuse(rel: str, finding: str) -> int | None:
    for i, (file, part, _why) in enumerate(EXEMPT):
        if file == rel and (part is None or part in finding):
            return i
    return None


def door_findings(root: pathlib.Path) -> list[str]:
    """The doors exist, carry one warning text, and that text is still the
    generator's where its source is checked out."""
    problems: list[str] = []
    try:
        rust = (root / RUST_DOOR).read_text(errors="replace")
    except OSError:
        return [f"the Rust door {RUST_DOOR} is missing"]
    try:
        shell = (root / SHELL_DOOR).read_text(errors="replace")
    except OSError:
        return [f"the shell door {SHELL_DOOR} is missing"]
    if "pub struct SceCodegen" not in rust:
        problems.append(f"{RUST_DOOR} no longer defines `pub struct SceCodegen`")
    if not re.search(r"^sce_codegen_spawn\(\) \{", shell, re.M):
        problems.append(f"{SHELL_DOOR} no longer defines sce_codegen_spawn()")
    rust_marker = RUST_MARKER_RE.search(rust)
    shell_marker = SHELL_MARKER_RE.search(shell)
    if rust_marker is None:
        problems.append(f"{RUST_DOOR} no longer states XSD_NOT_VALIDATED as a literal")
    if shell_marker is None:
        problems.append(f"{SHELL_DOOR} no longer states WZ_SCE_XSD_NOT_VALIDATED as a literal")
    if rust_marker and shell_marker and rust_marker.group(1) != shell_marker.group(1):
        problems.append(
            f"the doors look for different warnings: {rust_marker.group(1)!r} (Rust) "
            f"and {shell_marker.group(1)!r} (shell)"
        )
    if rust_marker:
        source = root / SCE_WARNING_SOURCE
        if source.is_file():
            if rust_marker.group(1) not in source.read_text(errors="replace"):
                problems.append(
                    f"{SCE_WARNING_SOURCE} no longer prints {rust_marker.group(1)!r}; "
                    "both doors would stop catching an unvalidated run"
                )
        else:
            print(
                f"  sce-codegen-spawn-lint: {SCE_WARNING_SOURCE} is not checked out; "
                "the warning text was not compared with the generator's"
            )
    return problems


def population(root: pathlib.Path) -> list[str]:
    out = subprocess.run(
        [
            "git", "-C", str(root), "ls-files", "-z", "--",
            "scripts", "crates", "xtask", "deploy", ".github", ".githooks",
        ],
        capture_output=True,
        check=True,
    ).stdout.decode()
    return [
        rel
        for rel in out.split("\0")
        if rel
        and not rel.startswith("crates/target")
        and (rel.endswith((".rs", ".py")) or is_shell(rel))
    ]


def run(root: pathlib.Path, files: list[str], floor: int = POPULATION_FLOOR) -> int:
    if len(files) < floor:
        print(
            f"sce-codegen-spawn-lint: FAIL -- {len(files)} file(s) read, under the floor of "
            f"{floor}; a lint that read nothing must not pass"
        )
        return 1
    violations: list[str] = []
    used: set[int] = set()
    for rel in files:
        if is_door(rel):
            continue
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
    doors = door_findings(root)
    if violations or stale or doors:
        for v in violations:
            print(f"  sce-codegen-spawn-lint: {v}")
        if violations:
            print(
                f"sce-codegen-spawn-lint: FAIL -- {len(violations)} spawn(s) of sce-codegen past "
                "its doors. Run it through wz_codegen_build::SceCodegen (Rust) or "
                "sce_codegen_spawn (shell, scripts/lib/sce-codegen-oracle.sh), which name the "
                "workspace, templates and schemas and refuse a run that did not validate"
            )
        for rel in stale:
            print(f"sce-codegen-spawn-lint: FAIL -- the exemption of {rel} excuses nothing; remove it")
        for p in doors:
            print(f"sce-codegen-spawn-lint: FAIL -- {p}")
        return 1
    print(
        f"  sce-codegen-spawn-lint: {len(files)} file(s) read, 0 spawn of sce-codegen past its "
        f"doors, {len(EXEMPT)} exemption(s) each still excusing a use"
    )
    return 0


RUST_DOOR_FIXTURE = (
    "pub struct SceCodegen {}\n"
    'pub const XSD_NOT_VALIDATED: &str = "XSD schema validation did not run";\n'
)
SHELL_DOOR_FIXTURE = (
    'WZ_SCE_XSD_NOT_VALIDATED="XSD schema validation did not run"\n'
    "sce_codegen_spawn() {\n    :\n}\n"
)
SCE_WARNING_FIXTURE = 'eprintln!("warning: XSD schema validation did not run -- {}");\n'


def selftest() -> int:
    bad = {
        "a.rs": 'let bin = dir.join("target/release/sce-codegen");\n',
        "b.rs": 'let bin = release.join(format!("sce-codegen{}", EXE_SUFFIX));\n',
        "c.rs": "let bin = wz_codegen_build::locate_sce_codegen(&ws);\n",
        "d.rs": 'cmd.arg("--workspace-root").arg(&ws);\n',
        "e.rs": 'cmd.env("SCE_SCHEMAS_DIR", &schemas);\n',
        "f.rs": "let out = Command::new(codegen.binary()).output();\n",
        "g.sh": '"$SCE_CODEGEN" generate --language rust "$x"\n',
        "h.sh": '"$SCE_CODEGEN" \\\n    generate \\\n    --language c11\n',
        "i.sh": "vendor/sce/target/release/sce-codegen --workspace-root x generate\n",
        "j.sh": 'export SCE_TEMPLATE_DIR="$ROOT/vendor/sce/tools/codegen/templates"\n',
        "k.yml": "      - run: ${WZ_SCE_CODEGEN_BIN} check sources/a.scxml\n",
        "l.py": 'subprocess.run(["vendor/sce/target/release/sce-codegen", "generate", p])\n',
        "m.py": 'env["SCE_SCHEMAS_DIR"] = str(schemas)\n',
    }
    good = {
        "a.rs": (
            "// let bin = dir.join(\"target/release/sce-codegen\");\n"
            'panic!("sce-codegen generate for {stem}: {refusal}");\n'
            "let codegen = wz_codegen_build::SceCodegen::locate(&ws);\n"
            'println!("cargo:rerun-if-changed={}", codegen.binary().display());\n'
            "let child = Command::new(zenohd_binary()).spawn();\n"
        ),
        "b.sh": (
            "# \"$SCE_CODEGEN\" generate --workspace-root x\n"
            'sce_codegen_spawn "$SCE_CODEGEN" "$ROOT/vendor/sce" "$err" \\\n'
            "    generate --language rust\n"
            "cargo build --release --features cli --bin sce-codegen\n"
            'echo "verify-codegen: sce-codegen is not the pinned build." >&2\n'
            'if [[ ! -x "$WZ_SCE_CODEGEN_BIN" ]]; then :; fi\n'
        ),
        "c.yml": "      - name: Build sce-codegen (vendor/sce)\n",
        "d.py": (
            '"""Runs `sce-codegen generate` with SCE_SCHEMAS_DIR named."""\n'
            'OWNERS = {"SCE_WORKSPACE_ROOT": ("foreign", "sce-codegen", ("x.py",))}\n'
            'EDGE = "wz-ap-demo-app:sce-codegen"\n'
        ),
    }
    failures = 0

    def expect(ok: bool, what: str) -> None:
        nonlocal failures
        if not ok:
            failures += 1
            print(f"sce-codegen-spawn-lint selftest FAIL: {what}")

    for rel, text in bad.items():
        expect(bool(findings_in(rel, text)), f"{rel} {text.strip()!r} was not caught")
    for rel, text in good.items():
        expect(not findings_in(rel, text), f"{rel} {findings_in(rel, text)} was caught")

    expect(is_door("crates/wz-codegen-build/tests/provenance.rs"), "the door crate's tests")
    expect(is_door(SHELL_DOOR), "the shell door")
    expect(not is_door("crates/wz-codegen-builder/src/lib.rs"), "a crate named like the door")
    expect(not is_door("scripts/verify-codegen.sh"), "a consumer of the shell door")

    def tree(base: pathlib.Path, rust: str, shell: str, sce: str | None) -> None:
        (base / RUST_DOOR).parent.mkdir(parents=True, exist_ok=True)
        (base / RUST_DOOR).write_text(rust)
        (base / SHELL_DOOR).parent.mkdir(parents=True, exist_ok=True)
        (base / SHELL_DOOR).write_text(shell)
        source = base / SCE_WARNING_SOURCE
        if sce is None:
            source.unlink(missing_ok=True)
        else:
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(sce)

    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        tree(base, RUST_DOOR_FIXTURE, SHELL_DOOR_FIXTURE, SCE_WARNING_FIXTURE)
        expect(not door_findings(base), f"sound doors were refused: {door_findings(base)}")
        tree(base, RUST_DOOR_FIXTURE, SHELL_DOOR_FIXTURE, None)
        expect(not door_findings(base), "an absent SCE checkout was refused")
        tree(
            base,
            RUST_DOOR_FIXTURE,
            SHELL_DOOR_FIXTURE.replace("did not run", "was skipped"),
            SCE_WARNING_FIXTURE,
        )
        expect(bool(door_findings(base)), "two doors looking for different words passed")
        tree(
            base,
            RUST_DOOR_FIXTURE,
            SHELL_DOOR_FIXTURE,
            SCE_WARNING_FIXTURE.replace("did not run", "was skipped"),
        )
        expect(bool(door_findings(base)), "a generator that changed its words passed")
        tree(base, RUST_DOOR_FIXTURE, "sce_codegen_run() {\n    :\n}\n", SCE_WARNING_FIXTURE)
        expect(bool(door_findings(base)), "a shell door with no spawn function passed")
        tree(base, RUST_DOOR_FIXTURE.replace("SceCodegen", "Codegen"), SHELL_DOOR_FIXTURE, None)
        expect(bool(door_findings(base)), "a Rust door with no SceCodegen passed")

        tree(base, RUST_DOOR_FIXTURE, SHELL_DOOR_FIXTURE, SCE_WARNING_FIXTURE)
        (base / "ok.sh").write_text(good["b.sh"])
        (base / "bad.sh").write_text(bad["g.sh"])
        expect(run(base, ["ok.sh"], floor=2) == 1, "a population under the floor passed")
        saved = list(EXEMPT)
        try:
            EXEMPT.clear()
            expect(run(base, ["ok.sh"], floor=1) == 0, "a clean population failed")
            expect(run(base, ["ok.sh", "bad.sh"], floor=1) == 1, "a direct spawn passed")
            expect(
                run(base, ["ok.sh", RUST_DOOR, SHELL_DOOR], floor=1) == 0,
                "a door's own spawn was refused",
            )
            EXEMPT.append(("ok.sh", None, "a test exemption"))
            expect(run(base, ["ok.sh"], floor=1) == 1, "an exemption that excuses nothing passed")
            EXEMPT[-1] = ("bad.sh", "generate", "a line-scoped test exemption")
            expect(run(base, ["ok.sh", "bad.sh"], floor=1) == 0, "a line exemption did not excuse")
            EXEMPT[-1] = ("bad.sh", "something else", "an exemption for another line")
            expect(run(base, ["ok.sh", "bad.sh"], floor=1) == 1, "a line exemption excused all")
        finally:
            EXEMPT.clear()
            EXEMPT.extend(saved)
    if failures:
        return 1
    print("sce-codegen-spawn-lint selftest: ok")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    if sys.argv[1:]:
        print("usage: sce_codegen_spawn_lint.py [--selftest]", file=sys.stderr)
        return 2
    return run(ROOT, population(ROOT))


if __name__ == "__main__":
    sys.exit(main())
