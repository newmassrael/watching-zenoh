#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4291 (no register item) -- merge a crate's integration test files into ONE test executable.

Cargo builds every `tests/<name>.rs` as a crate of its own and links it against the whole
dependency tree. The workspace holds 584 such files; one executable was 125 MB with the full debug
information (measured 2026-11-05), and a feature set of a gate leg builds them all again under
another hash, so Layer C1bnl's 99 legs took 90 GB of a build machine's disk. The remedy the Cargo
documentation and the Rust project's own crates give is one integration test target per crate: one
link, one copy of the code the tests share, and the files as modules.

The layout this tool makes, for a crate `C` whose files are `tests/<name>.rs`:

    tests/it/main.rs          `mod files;`          (cargo finds `tests/<dir>/main.rs` by itself),
                              and a helper module two files share, once (`shared_helpers`)
    tests/it/files/mod.rs     `mod <name>;` for every file moved, in order
    tests/it/files/<name>.rs  the file, moved with `git mv`, its text UNCHANGED but for a `crate::`
                              path of its code, which names the file's own module now

The test of a file is `files::<name>::<test>` and a script that ran one file ran
`--test <name>`, which is `--test it files::<name>::` now. libtest's filter is a substring and
`files::` is the prefix that makes it exact: `a::` is a substring of `b_a::`, `files::a::` is not
of `files::b_a::`.

A file is NOT merged when it must be its own process or cannot be a module:

  * it installs a `#[global_allocator]` (a binary has one, and an allocation count is read in a
    quiet process);
  * it has a `[[test]]` table in the crate's `Cargo.toml` that sets more than a `name` and a
    `required-features` list (a `path`, `harness`, `edition`): that table is the crate's own
    decision about the file. A table of a name and its required features IS dissolved (below);
  * it has `harness = false` or an `fn main` (it is not a libtest target);
  * it sets or removes an environment variable or changes the working directory
    (`PROCESS_WRITE`): every other file of a shared executable would run under what it set, as
    the key log of a TLS test set by `SSLKEYLOGFILE` collected every neighbour's sessions;
  * it calls into a registry the process owns (`PROCESS_REGISTRY`: the `wz_ext_*` clock, event
    log, supervisor, sampler and snapshot of the C ABI library), or says of itself that it needs
    "a process of its own" (`PROCESS_OWN`): a neighbour in the same process would read its state;
  * an explicit `--keep NAME` (a file that reads the process's environment, its working directory
    or a signal, which a neighbour in the same process could disturb).

An inner attribute of a file (`#![cfg(feature = "x")]`, `#![allow(...)]`) is valid at the top of a
module file and stays where it is: the file is then an empty module in a build without the feature,
as it was an empty executable.

A `[[test]]` table of a name and `required-features` is how a crate says "build this file only
with these features", and it is what kept such a file an executable of its own: cargo gates a
whole TARGET by that list, and a merged target holds files of every list. The same statement is a
file-level gate, `#![cfg(all(feature = "a", feature = "b"))]` at the top of the module file, which
removes the module (its tests, its imports, its helpers) from a build without those features. `--apply`
writes that attribute (with the comment that stood above the table, as the table's reason) and
deletes the table, so the crate builds ONE executable of the files its features enable, where it
built one for each. Every feature set of a gate leg then costs one executable and not k.

    merge_tests.py --crate C --plan           what would move, what stays, and why
    merge_tests.py --crate C --apply [--keep N]   `git mv` the files and write the two new ones
    merge_tests.py --compare BEFORE AFTER      the sets of (file, test) of two `cargo test -- --list`
                                               outputs are equal: the one invariant of the move
    merge_tests.py --selftest
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"

HEADER = """\
// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The integration tests of this crate, as ONE test executable.
//!
//! Every file of `files/` was a test file of `tests/` and so an executable of its own,
//! linked against the whole dependency tree; they are modules of this one now, and the test of a
//! file is `files::<name>::<test>` (`cargo test --test it files::<name>::` runs one file). The
//! files that must be their own process (a global allocator, a test table that sets more than the
//! features a file requires) stay in `tests/`. A file that required features carries them as an
//! inner `cfg` attribute at its top. See `scripts/lib/merge_tests.py`.

mod files;
"""

FILES_HEADER = """\
// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The test files of the crate, one module each. Generated by `scripts/lib/merge_tests.py`; a new
//! file of `files/` is named here by hand, in order.

"""

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# A call that changes what every thread of the process reads: its environment or its directory.
PROCESS_WRITE = re.compile(r"\benv::(set_var|remove_var)\s*\(|\bset_current_dir\s*\(")
# A call into a registry the PROCESS owns, which one executable per file kept apart: the observation
# plane's clock source, event log, supervisor, resource sampler and snapshot are statics of the C
# ABI library (`wz_ext_*` doors of `wz-capi-pico`), so two files that read or set them in one
# executable read each other's state. Measured 2026-11-06: exactly the seven files that had been
# kept by hand call them, and no other file of the C ABI crates does.
PROCESS_REGISTRY = re.compile(r"\bwz_ext_(?:clock|event|supervision|snapshot|resource)_\w+")
# A file that says of itself that it needs a process of its own (its header gives the reason).
PROCESS_OWN = re.compile(r"(?i)\b(?:in a process of its own|in its own process|needs? its own process)\b")
KEYWORDS = {
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use",
    "where", "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final",
    "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "gen",
}


def toml_tests(manifest: Path) -> set[str]:
    """The names and paths a `[[test]]` table of `manifest` gives a file of `tests/`."""
    text = manifest.read_text() if manifest.exists() else ""
    names: set[str] = set()
    for block in re.split(r"(?m)^\[\[test\]\]\s*$", text)[1:]:
        block = re.split(r"(?m)^\[", block)[0]
        for key in ("name", "path"):
            m = re.search(rf'(?m)^\s*{key}\s*=\s*"([^"]+)"', block)
            if m:
                value = m.group(1)
                names.add(Path(value).stem)
    return names


class TestTable:
    """One `[[test]]` table of a manifest: the test it names, the features it requires, whether it
    sets anything else (a path, `harness`, `test`, `edition`: such a table cannot be dissolved into
    the file), and the lines it occupies, with the comment right above it."""

    def __init__(self, name: str, features: list[str], simple: bool, first: int, last: int,
                 comment: list[str]):
        self.name = name
        self.features = features
        self.simple = simple
        self.first = first      # index of the first line to remove (its comment, if any)
        self.last = last        # index one past the last line to remove
        self.comment = comment  # the comment lines above the table, without the leading `#`


_KEY = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*(.*)$")


def test_tables(text: str) -> list[TestTable]:
    """The `[[test]]` tables of a manifest, in order. The table ends at the next line that opens a
    table and takes the blank lines after it; its comment is the run of `#` lines right above it
    (no blank line between). A value that opens an array and does not close it on its line is read
    to its `]`; only `name` and `required-features` keep a table simple."""
    lines = text.splitlines(keepends=True)
    tables: list[TestTable] = []
    i = 0
    while i < len(lines):
        if lines[i].strip() != "[[test]]":
            i += 1
            continue
        first = i
        while first > 0 and lines[first - 1].lstrip().startswith("#"):
            first -= 1
        comment = [ln.strip()[1:].strip() for ln in lines[first:i]]
        j = i + 1
        keys: dict[str, str] = {}
        while j < len(lines) and not lines[j].lstrip().startswith("["):
            m = _KEY.match(lines[j])
            if m:
                value = m.group(2)
                depth = value.count("[") - value.count("]")
                while depth > 0 and j + 1 < len(lines):
                    j += 1
                    value += lines[j]
                    depth += lines[j].count("[") - lines[j].count("]")
                keys[m.group(1)] = value
            j += 1
        last = j
        while last > i + 1 and not lines[last - 1].strip():
            last -= 1
        end = j  # the blank lines after the table go with it
        names = re.findall(r'"([^"]+)"', keys.get("name", ""))
        feats = re.findall(r'"([^"]+)"', keys.get("required-features", ""))
        simple = bool(names) and set(keys) <= {"name", "required-features"}
        tables.append(TestTable(names[0] if names else "", feats, simple, first, end, comment))
        i = j
    return tables


def remove_tables(text: str, names: set[str]) -> str:
    """`text` without the `[[test]]` tables called `names` (each with its comment above)."""
    lines = text.splitlines(keepends=True)
    for table in sorted(test_tables(text), key=lambda t: -t.first):
        if table.name in names:
            del lines[table.first:table.last]
    return "".join(lines)


def feature_gate(features: list[str]) -> str:
    """The inner attribute that makes a module file exist only when `features` are on."""
    parts = [f'feature = "{f}"' for f in features]
    return f"#![cfg({parts[0]})]" if len(parts) == 1 else f"#![cfg(all({', '.join(parts)}))]"


def insert_gate(text: str, gate: str, comment: list[str]) -> str:
    """`text` with `gate` (and `comment`, the manifest's words about the table) placed after the
    file's own opening comments and inner attributes, where an inner attribute may stand."""
    lines = text.splitlines(keepends=True)
    at = 0
    depth = 0
    in_block = False
    while at < len(lines):
        s = lines[at].strip()
        if in_block:
            in_block = "*/" not in s
        elif depth > 0:
            depth += s.count("[") - s.count("]")
        elif not s or s.startswith("//"):
            pass
        elif s.startswith("/*"):
            in_block = "*/" not in s
        elif s.startswith("#!["):
            depth = max(s.count("[") - s.count("]"), 0)
        else:
            break
        at += 1
    while at > 0 and not lines[at - 1].strip():
        at -= 1
    head = "".join(lines[:at])
    tail = "".join(lines[at:])
    add = "\n" if head else ""
    add += "".join(f"// {c}\n" if c else "//\n" for c in comment)
    add += gate + "\n"
    if tail and not tail.startswith("\n"):
        add += "\n"
    return head + add + tail


def families_of(text: str, exclusive: list[str]) -> list[str]:
    """The exclusive crates a file uses by path (`token::...`, `use token`), not in prose."""
    return [t for t in exclusive if re.search(rf"(?<![\w`]){t}::|\buse\s+{t}\b", text)]


def classify(
    crate: Path, keep: set[str], exclusive: list[str] | None = None
) -> tuple[dict[str, list[str]], list[tuple[str, str]]]:
    """({target: [names]}, [(name, why it stays)]) for the files `crate/tests/*.rs`.

    The target is `it` for a file that uses none of the `exclusive` crates and `it_<crate>` for
    one that uses that crate. Two crates are exclusive when one executable cannot link both: they
    export the same symbol (`zenoh_pico_sys`, the vendored C library, and `wz_capi_pico`, which is
    its drop-in, both define `z_close`), and a file used to link only the one it named."""
    exclusive = exclusive or []
    tests = crate / "tests"
    tabled = toml_tests(crate / "Cargo.toml")
    manifest = (crate / "Cargo.toml").read_text() if (crate / "Cargo.toml").exists() else ""
    # A table of a name and the features it requires is dissolved into the file (a file-level
    # `#![cfg]`, `apply`); a table that sets anything else cannot be, and its file stays.
    dissolvable = {t.name for t in test_tables(manifest) if t.simple}
    tabled = tabled - dissolvable
    harnessless = "harness = false" in manifest or "harness=false" in manifest
    merge: dict[str, list[str]] = {}
    stay: list[tuple[str, str]] = []
    for path in sorted(tests.glob("*.rs")):
        name = path.stem
        text = path.read_text()
        if name == "main":
            stay.append((name, "named main: it would be the crate root of a target of its own"))
        elif not IDENT.match(name) or name in KEYWORDS:
            stay.append((name, "its name is not a module name"))
        elif "#[global_allocator]" in text:
            stay.append((name, "installs a #[global_allocator]"))
        elif name in tabled:
            stay.append((name, "has a [[test]] table"))
        elif harnessless and re.search(r"(?m)^(pub )?fn main\s*\(", text):
            stay.append((name, "has its own fn main"))
        elif re.search(r"(?m)^(pub )?fn main\s*\(", text):
            stay.append((name, "has its own fn main"))
        elif PROCESS_REGISTRY.search(text):
            stay.append((name, "reads or sets a registry the process owns (`wz_ext_*` clock, event "
                               "log, supervisor, sampler, snapshot), which every file of a shared "
                               "executable would share"))
        elif PROCESS_OWN.search(text):
            stay.append((name, "says it needs a process of its own"))
        elif PROCESS_WRITE.search(text):
            stay.append((name, "changes the process's environment or working directory, which "
                               "every file of a shared executable reads"))
        elif name in keep:
            stay.append((name, "kept by --keep"))
        else:
            used = families_of(text, exclusive)
            if len(used) > 1:
                stay.append((name, f"links two exclusive crates: {', '.join(used)}"))
            else:
                target = f"it_{used[0]}" if used else "it"
                merge.setdefault(target, []).append(name)
    return merge, stay


def helper_modules(crate: Path, test_names: set[str]) -> dict[str, str]:
    """{module name: path from `tests/` of its source} for the helper modules of the crate: a
    `tests/<name>/mod.rs` (or a `tests/<name>.rs` that is not itself a test file) that test files
    declare with `mod <name>;`. Declared in a file that is a module now, that line would look for
    `tests/it/files/<file>/<name>.rs`; a `#[path]` to where the helper is keeps it. A helper that
    two or more files of one target declare is declared once, at the target's root, and each of
    those files `use`s it ([`shared_helpers`]): one source file loaded as two modules is what
    clippy's `duplicate_mod` refuses."""
    found: dict[str, str] = {}
    tests = crate / "tests"
    for sub in tests.iterdir():
        if sub.is_dir() and (sub / "mod.rs").is_file():
            found[sub.name] = f"{sub.name}/mod.rs"
    for path in tests.glob("*.rs"):
        if path.stem not in test_names and path.stem not in found:
            if any(re.search(rf"(?m)^\s*mod {re.escape(path.stem)};\s*$", p.read_text())
                   for p in tests.glob("*.rs") if p != path):
                found[path.stem] = f"{path.stem}.rs"
    return found


MOD_DECL = re.compile(r"(?m)^(?P<indent>[ \t]*)mod (?P<name>[A-Za-z_][A-Za-z0-9_]*);[ \t]*$")
# What makes a module's instance matter: state of the process (a static, a thread-local), which
# one executable per file held once per file and one shared module would hold once for all.
STATEFUL = re.compile(r"(?m)^\s*(pub(\([^)]*\))?\s+)?(static\s|thread_local!)")


def shared_helpers(texts: list[str], helpers: dict[str, str]) -> set[str]:
    """The helpers that two or more of `texts` (the files of one target) declare with `mod`."""
    count: dict[str, int] = {}
    for text in texts:
        for name in {m.group("name") for m in MOD_DECL.finditer(text)} & helpers.keys():
            count[name] = count.get(name, 0) + 1
    return {name for name, n in count.items() if n > 1}


def point_helper_modules(text: str, helpers: dict[str, str],
                         shared: frozenset[str] | set[str] = frozenset()) -> tuple[str, int]:
    """`text` with each `mod <helper>;` given a `#[path]` to the helper, from `tests/<t>/files/`,
    or, for a helper the target's root declares (`shared`), turned into `use crate::<helper>;`."""
    count = 0

    def sub(m: re.Match[str]) -> str:
        nonlocal count
        name = m.group("name")
        if name not in helpers:
            return m.group(0)
        count += 1
        if name in shared:
            return f'{m.group("indent")}use crate::{name};'
        return f'{m.group("indent")}#[path = "../../{helpers[name]}"]\n{m.group(0)}'

    return MOD_DECL.sub(sub, text), count


def reexecuters(crate: Path) -> list[str]:
    """The files that run their own test binary again (`current_exe`): they name a test of their
    own to the child (`--exact <name>`), and the name of a test is its module path now."""
    return [p.stem for p in sorted((crate / "tests").glob("*.rs"))
            if "current_exe" in p.read_text()]


def warn_reexec(names: list[str]) -> None:
    for name in names:
        print(f"  WARNING {name}: re-executes its own binary; the child's `--exact` name must be "
              f"the module path (`module_path!()` below the crate root), see merge_tests.py")


def plan(crate: Path, keep: set[str], exclusive: list[str]) -> int:
    merge, stay = classify(crate, keep, exclusive)
    warn_reexec(reexecuters(crate))
    print(f"{crate.name}: {sum(map(len, merge.values()))} file(s) merge into "
          f"{len(merge)} target(s), {len(stay)} stay")
    for target, names in sorted(merge.items()):
        print(f"  tests/{target}: {len(names)} file(s)")
    for name, why in stay:
        print(f"  stays   {name}: {why}")
    taken = [t for t in merge if (crate / "tests" / t).exists()]
    if taken:
        print(f"  ERROR: tests/{taken[0]} exists already")
        return 1
    return 0


def git(*args: str) -> None:
    subprocess.run(["git", *args], cwd=ROOT, check=True)


# `crate::` in the code of a test file named the file's own root, which was the crate root of its
# executable; it is a module now, at `crate::files::<name>`. A `$crate` of a macro is not it, and a
# comment is only text.
CRATE_PATH = re.compile(r"(?<![\w$`])crate::")
# A path in backticks is prose that quotes a path (a block comment or a string holds some), not code.


def rebase_crate_paths(text: str, name: str) -> tuple[str, list[str]]:
    """`text` with each `crate::` of its code made `crate::files::<name>::`, and the changed lines."""
    changed: list[str] = []
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        code, sep, comment = line.partition("//")
        new = CRATE_PATH.sub(f"crate::files::{name}::", code)
        if new != code:
            changed.append(line.rstrip("\n"))
        out.append(new + sep + comment)
    return "".join(out), changed


def apply(crate: Path, keep: set[str], exclusive: list[str]) -> int:
    merge, stay = classify(crate, keep, exclusive)
    if not merge:
        print("no file to merge", file=sys.stderr)
        return 1
    for target in merge:
        if (crate / "tests" / target).exists():
            print(f"tests/{target} exists already: nothing done", file=sys.stderr)
            return 1
    warn_reexec(reexecuters(crate))
    helpers = helper_modules(crate, {n for names in merge.values() for n in names}
                             | {n for n, _ in stay})
    rebased = 0
    moved = 0
    shared_by: dict[str, set[str]] = {}
    for target, names in sorted(merge.items()):
        shared = shared_helpers(
            [(crate / "tests" / f"{n}.rs").read_text() for n in names], helpers)
        stateful = sorted(h for h in shared
                          if STATEFUL.search((crate / "tests" / helpers[h]).read_text()))
        if stateful:
            print(f"tests/{target}: the helper(s) {', '.join(stateful)} hold a static or a "
                  f"thread-local, which each file's executable held once and one shared module "
                  f"would hold once for all: keep all but one of their files (--keep), or decide "
                  f"by hand. Nothing done", file=sys.stderr)
            return 1
        shared_by[target] = shared
    manifest_path = crate / "Cargo.toml"
    manifest = manifest_path.read_text() if manifest_path.exists() else ""
    dissolved = {t.name: t for t in test_tables(manifest) if t.simple}
    gated: set[str] = set()
    for target, names in sorted(merge.items()):
        it = crate / "tests" / target
        (it / "files").mkdir(parents=True)
        shared = shared_by[target]
        for name in names:
            src = crate / "tests" / f"{name}.rs"
            dst = it / "files" / f"{name}.rs"
            git("mv", str(src.relative_to(ROOT)), str(dst.relative_to(ROOT)))
            text, changed = rebase_crate_paths(dst.read_text(), name)
            text, pointed = point_helper_modules(text, helpers, shared)
            if pointed:
                print(f"  helper module pointed by #[path] in {name}")
            table = dissolved.get(name)
            if table is not None:
                gated.add(name)
                if table.features:
                    text = insert_gate(text, feature_gate(table.features), table.comment)
            if changed or pointed or table is not None:
                dst.write_text(text)
                rebased += len(changed)
                for line in changed:
                    print(f"  crate:: rewritten in {name}: {line.strip()}")
        (it / "main.rs").write_text(
            HEADER.replace("one test executable", f"the test executable `{target}`")
            + "".join(f'\n#[path = "../{helpers[h]}"]\nmod {h};\n' for h in sorted(shared)))
        (it / "files" / "mod.rs").write_text(FILES_HEADER + "".join(f"mod {n};\n" for n in names))
        git("add", str(it.relative_to(ROOT)))
        moved += len(names)
        print(f"  tests/{target}: {len(names)} file(s)")
    if gated:
        manifest_path.write_text(remove_tables(manifest, gated))
        print(f"  {len(gated)} [[test]] table(s) of Cargo.toml became a file-level feature gate")
    print(f"{crate.name}: {moved} file(s) moved into {len(merge)} target(s), {len(stay)} stay, "
          f"{rebased} line(s) with a crate:: path rebased")
    return 0


# A `cargo test -- --list` output: a `Running ...` header per executable, then `name: test` lines.
RUNNING = re.compile(r"^\s*Running (?:unittests )?(\S+)")
LISTED = re.compile(r"^(.*): (?:test|benchmark)$")


def listing(text: str, merged: bool) -> set[tuple[str, str]]:
    """The (file, test) pairs of one listing. Before the move the file is the executable's own
    name (`tests/<name>.rs`); after it, the first segment under `files::` of the `it` executable."""
    out: set[tuple[str, str]] = set()
    current = ""
    for line in text.splitlines():
        m = RUNNING.match(line)
        if m:
            target = Path(m.group(1))
            # `tests/<dir>/main.rs` is the target `<dir>`, `tests/<name>.rs` the target `<name>`.
            current = target.parent.name if target.name == "main.rs" else target.stem
            continue
        m = LISTED.match(line)
        if not m:
            continue
        test = m.group(1)
        if merged and (current == "" or current.startswith("it")) and test.startswith("files::"):
            _, name, rest = test.split("::", 2) if test.count("::") >= 2 else (None, None, None)
            if name is None:
                return out | {("<malformed>", test)}
            # A listing with no `Running` header (`--quiet`) does not say which file a test of the
            # old layout belonged to, so the file is left out of both sides.
            out.add((name if current else "", rest))
        else:
            out.add((current, test))
    return out


def compare(before: Path, after: Path) -> int:
    b = listing(before.read_text(), merged=False)
    a = listing(after.read_text(), merged=True)
    if not b:
        print("the listing before holds no test", file=sys.stderr)
        return 1
    only_b, only_a = sorted(b - a), sorted(a - b)
    print(f"before {len(b)} test(s), after {len(a)}")
    for pair in only_b[:20]:
        print(f"  only before: {pair}")
    for pair in only_a[:20]:
        print(f"  only after:  {pair}")
    return 0 if not only_b and not only_a else 1


def selftest() -> int:
    failures = 0

    def check(label: str, ok: bool) -> None:
        nonlocal failures
        if not ok:
            failures += 1
            print(f"selftest FAIL: {label}")

    before = "Running tests/a.rs (t/a)\nx: test\ny: test\nRunning tests/b.rs (t/b)\nz: test\n"
    after = ("Running tests/it/main.rs (t/it)\nfiles::a::x: test\nfiles::a::y: test\n"
             "files::b::z: test\n")
    check("equal sets", listing(before, False) == listing(after, True))
    short = "Running tests/it/main.rs (t/it)\nfiles::a::x: test\nfiles::b::z: test\n"
    check("a lost test is seen", listing(before, False) != listing(short, True))
    nested = "Running tests/it/main.rs (t/it)\nfiles::a::m::x: test\n"
    check("a nested module keeps its path", ("a", "m::x") in listing(nested, True))
    check("unit tests are not files", ("lib", "t") in listing(
        "Running unittests src/lib.rs (t/lib)\nt: test\n", False) or True)
    check("keywords are refused", "match" in KEYWORDS and "mod" in KEYWORDS)
    text, changed = rebase_crate_paths(
        "//! see `crate::agg`\nfn f() { crate::g(); $crate::h(); }\nlet s = x; // crate::y\n", "n")
    check("crate:: of code is rebased", "crate::files::n::g()" in text)
    check("a $crate is not", "$crate::h()" in text)
    check("a comment is not", "// crate::y" in text and "`crate::agg`" in text)
    check("prose quoting a path is not", rebase_crate_paths("  as a test in `crate::scout`.\n", "n")[1] == [])
    check("one line changed", len(changed) == 1)
    check("an unchanged file has no change", rebase_crate_paths("fn f() {}\n", "n")[1] == [])
    with tempfile.TemporaryDirectory() as tmp:
        crate = Path(tmp) / "c"
        (crate / "tests").mkdir(parents=True)
        (crate / "Cargo.toml").write_text(
            '[package]\nname = "c"\n\n[[test]]\nname = "tabled"\npath = "tests/tabled.rs"\n')
        for name, body in {
            "plain": "#[test] fn t() {}\n",
            "alloc": "#[global_allocator]\nstatic A: u8 = 0;\n",
            "tabled": "#[test] fn t() {}\n",
            "mainful": "fn main() {}\n",
            "gated": '#![cfg(feature = "x")]\n#[test] fn t() {}\n',
            "kept": "#[test] fn t() {}\n",
            "9bad": "#[test] fn t() {}\n",
            "envset": '#[test] fn t() { std::env::set_var("SSLKEYLOGFILE", "x"); }\n',
            "envread": '#[test] fn t() { let _ = std::env::var("HOME"); }\n',
            "registry": "#[test] fn t() { unsafe { wz_ext_event_emit(0); } }\n",
            "ownproc": "//! One test, in a process of its own, because the log is the process's.\n"
                       "#[test] fn t() {}\n",
            "prose": "//! The doors wz_ext are described in the book.\n#[test] fn t() {}\n",
        }.items():
            (crate / "tests" / f"{name}.rs").write_text(body)
        merge, stay = classify(crate, {"kept"})
        check("merge set", merge == {"it": ["envread", "gated", "plain", "prose"]})
        check("stay set", {n for n, _ in stay}
              == {"alloc", "tabled", "mainful", "kept", "9bad", "envset", "registry", "ownproc"})
        check("a call into a process registry keeps a file, prose naming the family does not",
              "registry" in {n for n, _ in stay} and "prose" not in {n for n, _ in stay})
        (crate / "tests" / "envset.rs").unlink()
        (crate / "tests" / "envread.rs").unlink()
        (crate / "tests" / "pico.rs").write_text("use zenoh_pico_sys::z_close;\n")
        (crate / "tests" / "drop_in.rs").write_text("use wz_capi_pico::z_close;\n")
        (crate / "tests" / "both.rs").write_text("use zenoh_pico_sys::a;\nuse wz_capi_pico::b;\n")
        (crate / "tests" / "prose.rs").write_text("//! about `zenoh_pico_sys::z_close`\nfn f() {}\n")
        merge, stay = classify(crate, {"kept"}, ["zenoh_pico_sys", "wz_capi_pico"])
        check("an exclusive crate makes a target of its own",
              merge.get("it_zenoh_pico_sys") == ["pico"]
              and merge.get("it_wz_capi_pico") == ["drop_in"])
        check("prose quoting a crate is not a use", "prose" in merge.get("it", []))
        check("a file of two exclusive crates stays", ("both", "links two exclusive crates: "
              "zenoh_pico_sys, wz_capi_pico") in stay)
        check("a target name is read back", ("a", "t") in listing(
            "Running tests/it_x/main.rs (t/it_x)\nfiles::a::t: test\n", True))
        (crate / "tests" / "harness").mkdir()
        (crate / "tests" / "harness" / "mod.rs").write_text("pub fn h() {}\n")
        (crate / "tests" / "uses.rs").write_text("mod harness;\n#[test] fn t() { harness::h() }\n")
        helpers = helper_modules(crate, {"uses", "plain"})
        check("a helper dir is found", helpers.get("harness") == "harness/mod.rs")
        text, n = point_helper_modules("mod harness;\nmod other;\n", helpers)
        check("a helper module gets a path and another does not",
              n == 1 and text == '#[path = "../../harness/mod.rs"]\nmod harness;\nmod other;\n')
        check("a helper two files declare is shared, one file's is not",
              shared_helpers(["mod harness;\n", "mod harness;\nmod other;\n", "mod other;\n"],
                             helpers) == {"harness"}
              and shared_helpers(["mod harness;\n"], helpers) == set())
        text, n = point_helper_modules("    mod harness;\n", helpers, {"harness"})
        check("a shared helper is used from the root, not declared again",
              n == 1 and text == "    use crate::harness;\n")
        check("a static or a thread-local is state, a fn is not",
              bool(STATEFUL.search("pub static X: u8 = 0;\n"))
              and bool(STATEFUL.search("thread_local! { }\n"))
              and not STATEFUL.search("pub fn h() {}\n// a static note\n"))
        check("a [[test]] name is read", toml_tests(crate / "Cargo.toml") == {"tabled"})
    manifest = (
        '[package]\nname = "c"\n\n'
        "# `peer` selects no engine, so a test that reaches the tokio engine says so.\n"
        "# Second line.\n"
        '[[test]]\nname = "a"\nrequired-features = ["peer", "query"]\n\n'
        '[[test]]\nname = "b"\nrequired-features = [\n    "x",\n    "y",\n]\n\n'
        '[[test]]\nname = "c"\npath = "tests/c.rs"\n\n'
        '[[test]]\nname = "d"\nharness = false\n\n'
        '[features]\npeer = []\n'
    )
    tables = {t.name: t for t in test_tables(manifest)}
    check("four tables are read", list(tables) == ["a", "b", "c", "d"])
    check("features of a one-line array", tables["a"].features == ["peer", "query"])
    check("features of a multi-line array", tables["b"].features == ["x", "y"])
    check("a path or harness keeps a table from being dissolved",
          tables["a"].simple and tables["b"].simple and not tables["c"].simple
          and not tables["d"].simple)
    check("the comment above a table goes with it", tables["a"].comment ==
          ["`peer` selects no engine, so a test that reaches the tokio engine says so.", "Second line."])
    gone = remove_tables(manifest, {"a", "b"})
    check("a removed table takes its comment and nothing else",
          "required-features" not in gone and "Second line" not in gone
          and '[[test]]\nname = "c"' in gone and '[features]\npeer = []\n' in gone
          and gone.startswith('[package]\nname = "c"\n\n[[test]]\nname = "c"'))
    check("removing no table changes nothing", remove_tables(manifest, {"zzz"}) == manifest)
    check("a one-feature gate", feature_gate(["peer"]) == '#![cfg(feature = "peer")]')
    check("a gate of two features", feature_gate(["a", "b"]) == '#![cfg(all(feature = "a", feature = "b"))]')
    opened = insert_gate(
        "// SPDX\n\n//! Docs.\n#![allow(\n    dead_code,\n)]\n\nuse a::b;\n#[test] fn t() {}\n",
        feature_gate(["x"]), ["why"])
    check("the gate follows the file's own inner attributes",
          opened == "// SPDX\n\n//! Docs.\n#![allow(\n    dead_code,\n)]\n\n// why\n"
                    '#![cfg(feature = "x")]\n\nuse a::b;\n#[test] fn t() {}\n')
    bare = insert_gate("use a::b;\n", feature_gate(["x"]), [])
    check("a file with no header takes the gate first", bare == '#![cfg(feature = "x")]\n\nuse a::b;\n')
    with tempfile.TemporaryDirectory() as tmp:
        crate = Path(tmp) / "c"
        (crate / "tests").mkdir(parents=True)
        (crate / "Cargo.toml").write_text(manifest)
        for name in "abcd":
            (crate / "tests" / f"{name}.rs").write_text("#[test] fn t() {}\n")
        merge, stay = classify(crate, set())
        check("a table of features is dissolved and any other table keeps its file",
              merge == {"it": ["a", "b"]} and {n for n, _ in stay} == {"c", "d"})
    if failures == 0:
        print("merge_tests: selftest OK")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--crate")
    ap.add_argument("--keep", default="", help="comma-separated file names that stay")
    ap.add_argument("--exclusive", default="",
                    help="comma-separated crates one executable cannot link together: a file that "
                         "uses one goes to the target `it_<crate>`, so each target links one")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan", action="store_true")
    group.add_argument("--apply", action="store_true")
    group.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    group.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.compare:
        return compare(Path(args.compare[0]), Path(args.compare[1]))
    if not args.crate:
        ap.error("--crate is required")
    crate = CRATES / args.crate
    if not (crate / "tests").is_dir():
        print(f"{crate} has no tests/", file=sys.stderr)
        return 1
    keep = {n for n in args.keep.split(",") if n}
    exclusive = [n for n in args.exclusive.split(",") if n]
    return plan(crate, keep, exclusive) if args.plan else apply(crate, keep, exclusive)


if __name__ == "__main__":
    sys.exit(main())
