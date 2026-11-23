#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4617 (no register item) -- the release code of the C ABI library's core crates is total, and
what is not yet total is a register that only shrinks.

The round cited is main's at the commit this gate was written on: the decision it holds
(docs/c-abi-architecture.md, principle P6 and migration step 2) has no round of its own yet, and
no register item named it.

## Why

P6 of the C ABI library's target structure: no panic is reachable from input. Indexing is checked
by construction (`get`, iterators, views of a known length), arithmetic is checked or saturating,
and every refusal is a value. The compiler enforces it with clippy's restriction lints, denied at
the root of each crate of CRATES outside a test build (ROOT_LINTS). The crates were written before
the rule, so a module not yet converted is allowed the lints BY NAME, at its declaration in the
crate root, with the row of the totality debt register (section 7 of that document) that says
which lints it still needs. Without this gate the allows are attributes anyone can add: a new
module could start allowed, an allow could move onto an item, and the register would drift from
the code it describes.

## What is held

1. ROOT. Each crate root carries `#![cfg_attr(not(test), deny(..))]` naming every lint of LINTS.
2. SHAPE. A totality lint is allowed in one place only: an outer `#[allow(..)]` of totality lints
   alone, on a `mod` item of the crate root, with the line above it naming its row
   (`// Totality debt TD-NNN (docs/c-abi-architecture.md section 7).`). Any other allow of a
   totality lint is refused: an inner one, one on an item, one under `cfg_attr`, an `expect` or a
   `warn`, and the `clippy::restriction` group, which holds them all.
3. REGISTER. The rows and the attributes agree both ways: every allowed module has its row, with
   the same id, crate and lints, and every row has its allowed module.
4. SITES. For the lints a text read can see -- the `unwrap` and `expect` calls and the panicking
   macros -- a module's row lists exactly what its non-test source holds. A site in a module the
   row does not cover is refused (clippy refuses it after a build; this says so before one). A
   listed lint with no site left is refused too: the row shrinks with its module. A module whose
   source includes generated code (`include!`) is read for the first direction only, since the
   generated text is not read here. Indexing and arithmetic cannot be decided from text, so their
   rows are held by the build's clippy alone.
5. RATCHET. No row has an id past LAST_ID, the last one given when the lints were switched on, so
   no debt is ever added. The register's lint cells equal CELLS: above it debt grew, which is
   refused; below it debt was paid, and CELLS is lowered in that same commit.

What this cannot see, stated rather than implied: a site that a macro of another crate expands
into a module, and an allow a build script writes into generated source.

Usage:
    python3 scripts/lib/totality_debt_gate.py --check
    python3 scripts/lib/totality_debt_gate.py --selftest
"""

from __future__ import annotations

import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rust_comments  # noqa: E402  -- after the path insert that finds it
from subsystem_spawn_gate import cfg_test_files, cfg_test_spans  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The crates whose release code is held total (the release C ABI library's core).
CRATES: tuple[str, ...] = ("wz-session-core", "wz-capi-coop", "wz-capi-pico", "wz-runtime-coop")

#: The register, relative to the root.
REGISTER = "docs/c-abi-architecture.md"

#: The heading of the register's section in it.
REGISTER_HEADING = "## 7. Totality debt register"

#: The totality lints, in the order a row and an attribute name them.
LINTS: tuple[str, ...] = (
    "indexing_slicing",
    "unwrap_used",
    "expect_used",
    "panic",
    "unreachable",
    "todo",
    "unimplemented",
    "arithmetic_side_effects",
)

#: The lints a text read decides, and the site each one is.
SITE_PATTERNS: dict[str, re.Pattern[str]] = {
    "unwrap_used": re.compile(r"\.\s*unwrap(?:_err)?\s*\(\s*\)"),
    "expect_used": re.compile(r"\.\s*expect(?:_err)?\s*\("),
    "panic": re.compile(r"(?<![\w])panic!\s*[(\[{]"),
    "unreachable": re.compile(r"(?<![\w])unreachable!\s*[(\[{]"),
    "todo": re.compile(r"(?<![\w])todo!\s*[(\[{]"),
    "unimplemented": re.compile(r"(?<![\w])unimplemented!\s*[(\[{]"),
}

#: The last id the register gave. A row past it is debt added after the lints were switched on.
LAST_ID = 206

#: The register's lint cells: every lint every row lists.
CELLS = 210

ID_COMMENT = re.compile(r"^\s*// Totality debt (TD-\d{3}) \(docs/c-abi-architecture\.md section 7\)\.\s*$")
ROW = re.compile(r"^\|\s*(TD-\d{3})\s*\|([^|]*)\|([^|]*)\|([^|]*)\|")
ROOT_ATTR = re.compile(
    r"#!\[\s*cfg_attr\s*\(\s*not\s*\(\s*test\s*\)\s*,\s*deny\s*\(([^()]*)\)\s*\)\s*\]"
)
LEVEL = re.compile(r"\b(allow|expect|warn)\s*\(([^()]*)\)")
MOD_ITEM = re.compile(r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*([;{])")
MOD_DECL = re.compile(
    r"((?:#\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\]\s*)*)(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*([;{])"
)
PATH_ATTR = re.compile(r"\bpath\s*=\s*\"([^\"]+)\"")


class InputError(Exception):
    """An input this gate could not read. Reported as a FAIL, never a traceback."""


@dataclass
class Row:
    ident: str
    crate: str
    module: str
    lints: tuple[str, ...]
    line: int


@dataclass
class Allowed:
    ident: str
    lints: tuple[str, ...]
    where: str


@dataclass
class Crate:
    name: str
    #: module -> the files of its subtree (non-test), for a module declared out of line
    files: dict[str, list[Path]] = field(default_factory=dict)
    #: module -> the text of its inline block in the root, for a module declared inline
    inline: dict[str, str] = field(default_factory=dict)


def lint_names(group: str) -> list[str]:
    return [name.strip() for name in group.split(",") if name.strip()]


def is_totality(name: str) -> bool:
    return name == "clippy::restriction" or (
        name.startswith("clippy::") and name[len("clippy::"):] in LINTS
    )


def line_of(text: str, at: int) -> int:
    return text.count("\n", 0, at) + 1


def match_bracket(text: str, start: int, open_: str, close: str) -> int:
    """The index of the bracket closing the one at `start`, or the text's length."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == open_:
            depth += 1
        elif text[i] == close:
            depth -= 1
            if depth == 0:
                return i
    return len(text)


def read_register(path: Path) -> list[Row]:
    if not path.is_file():
        raise InputError(f"no register at {path}")
    lines = path.read_text(encoding="utf-8").splitlines()
    try:
        start = lines.index(REGISTER_HEADING)
    except ValueError:
        raise InputError(f"{path} has no section '{REGISTER_HEADING}'") from None
    rows: list[Row] = []
    for number, line in enumerate(lines[start + 1:], start + 2):
        if line.startswith("## "):
            break
        m = ROW.match(line)
        if m is None:
            continue
        lints = tuple(name.strip(" `") for name in m.group(4).split(",") if name.strip(" `"))
        rows.append(Row(m.group(1), m.group(2).strip(" `"), m.group(3).strip(" `"), lints, number))
    return rows


def _children(rel: Path, text: str, src: Path) -> list[tuple[str, list[Path], str | None]]:
    """The modules the file `rel` (its text `text`) declares outside its test spans: (name, the
    files a declaration out of line may name, the text of one declared inline)."""
    stripped = rust_comments.strip_comments(text, blank_literals=True)
    # The literals of a `path` attribute are read where the comments are gone and they are not.
    kept = rust_comments.strip_comments(text)
    paths: dict[str, list[str]] = {}
    for m in MOD_DECL.finditer(kept):
        paths.setdefault(m.group(2), []).extend(PATH_ATTR.findall(m.group(1)))
    rootish = rel.name in ("lib.rs", "mod.rs")
    child_dir = rel.parent if rootish else rel.with_suffix("")
    skip = cfg_test_spans(stripped)
    inline: list[tuple[int, int, str]] = []
    decls = [m for m in MOD_DECL.finditer(stripped) if not any(a <= m.start(2) <= b for a, b in skip)]
    for m in decls:
        if m.group(3) == "{":
            inline.append((m.end(3) - 1, match_bracket(stripped, m.end(3) - 1, "{", "}"), m.group(2)))
    found: list[tuple[str, list[Path], str | None]] = []
    for m in decls:
        name = m.group(2)
        if m.group(3) == "{":
            end = match_bracket(stripped, m.end(3) - 1, "{", "}")
            found.append((name, [], stripped[m.end(3) - 1:end + 1]))
            continue
        enclosing = [n for a, b, n in sorted(inline) if a < m.start(2) < b]
        base = child_dir.joinpath(*enclosing) if enclosing else child_dir
        candidates = [base / f"{name}.rs", base / name / "mod.rs"]
        for p in paths.get(name, []):
            candidates.append((child_dir.joinpath(*enclosing) if enclosing else rel.parent) / p)
        found.append((name, [c for c in candidates if (src / c).is_file()], None))
    return found


def walk(src: Path) -> Crate:
    """The crate under `src`: each module its root declares, with the non-test files of its
    subtree or the text of its inline block."""
    root = Path("lib.rs")
    if not (src / root).is_file():
        raise InputError(f"no crate root at {src / root}")
    test_only = cfg_test_files(sorted(src.rglob("*.rs")))
    crate = Crate(src.parent.name)
    root_text = (src / root).read_text(encoding="utf-8", errors="replace")
    for name, files, block in _children(root, root_text, src):
        if block is not None:
            crate.inline[name] = block
            continue
        seen: list[Path] = []
        todo = [f for f in files if (src / f).resolve() not in test_only]
        while todo:
            rel = todo.pop()
            if rel in seen:
                continue
            seen.append(rel)
            text = (src / rel).read_text(encoding="utf-8", errors="replace")
            for _, more, _ in _children(rel, text, src):
                todo.extend(f for f in more if (src / f).resolve() not in test_only)
        crate.files.setdefault(name, []).extend(seen)
    return crate


def sites(text: str) -> dict[str, int]:
    """How many sites of each text-read lint `text` (stripped) holds outside its test spans."""
    skip = cfg_test_spans(text)
    counts: dict[str, int] = {}
    for lint, pattern in SITE_PATTERNS.items():
        n = sum(1 for m in pattern.finditer(text) if not any(a <= m.start() <= b for a, b in skip))
        if n:
            counts[lint] = n
    return counts


def allows(src: Path, findings: list[str]) -> dict[str, Allowed]:
    """Every allow of a totality lint in the non-test source of the crate at `src`, by module;
    one in any other shape is a finding."""
    found: dict[str, Allowed] = {}
    test_only = cfg_test_files(sorted(src.rglob("*.rs")))
    for path in sorted(src.rglob("*.rs")):
        if path.resolve() in test_only:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        stripped = rust_comments.strip_comments(text, blank_literals=True)
        skip = cfg_test_spans(stripped)
        lines = text.splitlines()
        rel = path.relative_to(src.parents[2])
        for m in re.finditer(r"#\s*(!?)\s*\[", stripped):
            if any(a <= m.start() <= b for a, b in skip):
                continue
            close = match_bracket(stripped, m.end() - 1, "[", "]")
            attr = stripped[m.start():close + 1]
            levels = LEVEL.findall(attr)
            named = [n for _, group in levels for n in lint_names(group)]
            if not any(is_totality(n) for n in named):
                continue
            line = line_of(stripped, m.start())
            where = f"{rel}:{line}"
            plain = re.fullmatch(r"#\[\s*allow\s*\(([^()]*)\)\s*\]", " ".join(attr.split()))
            if path.name != "lib.rs" or path.parent != src or m.group(1) or plain is None:
                findings.append(
                    f"{where}: a totality lint is allowed outside the one place it may be "
                    f"({' '.join(attr.split())}); convert the code, which is what P6 asks, or name "
                    f"the module at its declaration in the crate root under its register row"
                )
                continue
            names = lint_names(plain.group(1))
            if not all(n.startswith("clippy::") and n[len("clippy::"):] in LINTS for n in names):
                findings.append(
                    f"{where}: the allow names something but totality lints ({', '.join(names)}); "
                    f"a group or another lint does not share a debt attribute"
                )
                continue
            rest = stripped[close + 1:]
            while True:
                rest = rest.lstrip()
                if rest.startswith("#["):
                    rest = rest[match_bracket(rest, 1, "[", "]") + 1:]
                    continue
                break
            item = MOD_ITEM.match(rest)
            if item is None:
                findings.append(f"{where}: a totality allow is on an item that is not a module")
                continue
            above = next((lines[i] for i in range(line - 2, -1, -1) if lines[i].strip()), "")
            ident = ID_COMMENT.match(above)
            if ident is None:
                findings.append(
                    f"{where}: the allow of module {item.group(1)} has no line above it naming "
                    f"its row (// Totality debt TD-NNN (docs/c-abi-architecture.md section 7).)"
                )
                continue
            lints = tuple(n[len("clippy::"):] for n in names)
            previous = found.get(item.group(1))
            if previous is not None and (previous.ident, previous.lints) != (ident.group(1), lints):
                findings.append(
                    f"{where}: module {item.group(1)} is allowed twice, differently "
                    f"({previous.where})"
                )
                continue
            found[item.group(1)] = Allowed(ident.group(1), lints, where)
    return found


def grade(root: Path, crates: tuple[str, ...], last_id: int, cells: int) -> tuple[list[str], int, int]:
    """The findings over the crates under `root` and the register in it, how many rows it holds
    and how many lint cells."""
    findings: list[str] = []
    rows = read_register(root / REGISTER)
    by_key: dict[tuple[str, str], Row] = {}
    ids: set[str] = set()
    for row in rows:
        where = f"{REGISTER}:{row.line}"
        if row.ident in ids:
            findings.append(f"{where}: {row.ident} is given twice")
        ids.add(row.ident)
        if int(row.ident[3:]) > last_id:
            findings.append(
                f"{where}: {row.ident} is past {f'TD-{last_id:03}'}, the last id the register gave; "
                f"new code is total, and no debt row is added"
            )
        if row.crate not in crates:
            findings.append(f"{where}: {row.ident} names {row.crate}, which is not a held crate")
        unknown = [n for n in row.lints if n not in LINTS]
        if unknown or not row.lints:
            findings.append(f"{where}: {row.ident} lists {', '.join(unknown) or 'no lint'}")
        if tuple(n for n in LINTS if n in row.lints) != row.lints:
            findings.append(f"{where}: {row.ident} lists its lints out of the register's order")
        if (row.crate, row.module) in by_key:
            findings.append(f"{where}: {row.crate}::{row.module} has two rows")
        by_key[(row.crate, row.module)] = row
    total = sum(len(row.lints) for row in rows)
    if total > cells:
        findings.append(
            f"the register holds {total} lint cells, above the {cells} the ratchet holds: debt "
            f"grew; convert the code instead"
        )
    elif total < cells:
        findings.append(
            f"the register holds {total} lint cells, below the {cells} the ratchet holds: lower "
            f"CELLS to {total} in this commit"
        )
    for name in crates:
        src = root / "crates" / name / "src"
        lib = src / "lib.rs"
        if not lib.is_file():
            raise InputError(f"{name}: no crate root at {lib}")
        stripped = rust_comments.strip_comments(lib.read_text(encoding="utf-8"), blank_literals=True)
        denied = [set(lint_names(m.group(1))) for m in ROOT_ATTR.finditer(stripped)]
        want = {f"clippy::{n}" for n in LINTS}
        if not any(d == want for d in denied):
            findings.append(
                f"{name}: the crate root does not deny every totality lint outside a test build "
                f"(#![cfg_attr(not(test), deny({', '.join(sorted(want))}))])"
            )
        allowed = allows(src, findings)
        crate = walk(src)
        for module, got in sorted(allowed.items()):
            row = by_key.get((name, module))
            if row is None:
                findings.append(
                    f"{got.where}: module {module} is allowed under {got.ident}, which the register "
                    f"has no row for"
                )
                continue
            if (row.ident, row.lints) != (got.ident, got.lints):
                findings.append(
                    f"{got.where}: module {module} is allowed as {got.ident} "
                    f"({', '.join(got.lints)}), and its row says {row.ident} ({', '.join(row.lints)})"
                )
        for (crate_name, module), row in sorted(by_key.items()):
            if crate_name == name and module not in allowed:
                findings.append(
                    f"{REGISTER}:{row.line}: {row.ident} ({name}::{module}) allows nothing in the "
                    f"code; take the row off the register and lower CELLS"
                )
        modules = set(crate.files) | set(crate.inline)
        for module in sorted(modules):
            texts = [crate.inline[module]] if module in crate.inline else [
                rust_comments.strip_comments(
                    (src / rel).read_text(encoding="utf-8", errors="replace"), blank_literals=True
                )
                for rel in crate.files[module]
            ]
            held: dict[str, int] = {}
            for text in texts:
                for lint, n in sites(text).items():
                    held[lint] = held.get(lint, 0) + n
            generated = any("include!" in text for text in texts)
            listed = set(allowed[module].lints) if module in allowed else set()
            for lint in sorted(set(held) - listed):
                findings.append(
                    f"{name}::{module}: {held[lint]} site(s) of {lint} that nothing allows; "
                    f"clippy refuses them after a build: make the code total"
                )
            if not generated:
                for lint in sorted(listed & set(SITE_PATTERNS) - set(held)):
                    findings.append(
                        f"{name}::{module}: the row lists {lint} and the module has no site of it "
                        f"left; drop it from the row and the attribute, and lower CELLS"
                    )
    return findings, len(rows), total


def check() -> int:
    try:
        findings, rows, total = grade(REPO_ROOT, CRATES, LAST_ID, CELLS)
    except (InputError, OSError, UnicodeDecodeError) as e:
        print(f"totality-debt: FAIL -- cannot grade: {e}", file=sys.stderr)
        return 1
    if findings:
        print("totality-debt: FAIL", file=sys.stderr)
        for line in findings:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print(
        f"totality-debt: OK -- {len(CRATES)} crate(s) deny the totality lints; {rows} module(s) "
        f"of the register still allow {total} lint cell(s), none past TD-{LAST_ID:03}"
    )
    return 0


ROOT_TEXT = (
    "#![no_std]\n"
    "#![cfg_attr(\n    not(test),\n    deny(\n"
    + "".join(f"        clippy::{n},\n" for n in LINTS)
    + "    )\n)]\n"
)
REGISTER_HEAD = f"# Doc\n\n{REGISTER_HEADING}\n\n| id | crate | module | lints |\n|---|---|---|---|\n"


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _fixture(
    root: Path,
    *,
    lib_extra: str = "",
    debt_attr: str = "#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]\n",
    debt_comment: str = "// Totality debt TD-001 (docs/c-abi-architecture.md section 7).\n",
    debt_body: str = "pub fn f(x: Option<u8>) -> u8 {\n    x.unwrap() + 1\n}\n",
    clean_body: str = "pub fn g(x: Option<u8>) -> u8 {\n    x.unwrap_or(0)\n}\n",
    rows: str = "| TD-001 | `demo` | `debt` | `unwrap_used`, `arithmetic_side_effects` |\n",
    root_text: str = ROOT_TEXT,
) -> None:
    """A crate `demo` with a module under debt and a clean one, and the register over them."""
    _write(
        root,
        "crates/demo/src/lib.rs",
        root_text + debt_comment + debt_attr + "pub mod debt;\npub mod clean;\n"
        "#[cfg(test)]\nmod tests;\n" + lib_extra,
    )
    _write(root, "crates/demo/src/debt.rs", debt_body)
    _write(root, "crates/demo/src/clean.rs", clean_body)
    _write(root, "crates/demo/src/tests.rs", "fn t() {\n    Some(1).unwrap();\n}\n")
    _write(root, REGISTER, REGISTER_HEAD + rows + "\n## 8. Next\n\n| TD-999 | x | y | z |\n")


def selftest() -> int:
    """Drive every rule over a fixture crate, in both directions. A case is passed when a finding
    carries its words; the case that agrees has none."""
    failures: list[str] = []
    gen = "pub mod sm {\n    include!(concat!(env!(\"OUT\"), \"/sm.rs\"));\n}\n"
    # (name, fixture arguments, a substring one finding carries, or None for no finding)
    cases: list[tuple[str, dict, str | None]] = [
        ("agrees", {}, None),
        ("a root without the lints", {"root_text": "#![no_std]\n"}, "does not deny every"),
        (
            "a root missing one lint",
            {"root_text": ROOT_TEXT.replace("        clippy::todo,\n", "")},
            "does not deny every",
        ),
        (
            "an allow on an item",
            {"clean_body": "#[allow(clippy::unwrap_used)]\npub fn g(x: Option<u8>) -> u8 {\n"
                           "    x.unwrap()\n}\n"},
            "outside the one place",
        ),
        (
            "an inner allow",
            {"clean_body": "#![allow(clippy::indexing_slicing)]\npub fn g() {}\n"},
            "outside the one place",
        ),
        (
            "an allow under cfg_attr",
            {"lib_extra": "#[cfg_attr(feature = \"x\", allow(clippy::panic))]\npub mod more {}\n"},
            "outside the one place",
        ),
        (
            "the restriction group",
            {"lib_extra": "// Totality debt TD-002 (docs/c-abi-architecture.md section 7).\n"
                          "#[allow(clippy::restriction)]\npub mod more {}\n"},
            "something but totality lints",
        ),
        (
            "an expect of a lint",
            {"lib_extra": "#[expect(clippy::panic)]\npub mod more {}\n"},
            "outside the one place",
        ),
        ("an allow with no row named", {"debt_comment": ""}, "no line above it naming"),
        (
            "an allow mixed with another lint",
            {"debt_attr": "#[allow(clippy::unwrap_used, dead_code)]\n"},
            "something but totality lints",
        ),
        (
            "an allow the register has no row for",
            {"rows": ""},
            "which the register has no row for",
        ),
        (
            "a row whose lints differ",
            {"rows": "| TD-001 | `demo` | `debt` | `unwrap_used` |\n"},
            "and its row says TD-001 (unwrap_used)",
        ),
        (
            "a row with no allow in the code",
            {"debt_attr": "#[allow(clippy::unwrap_used)]\n",
             "rows": "| TD-001 | `demo` | `debt` | `unwrap_used` |\n"
                     "| TD-002 | `demo` | `gone` | `panic` |\n"},
            "allows nothing in the code",
        ),
        (
            "a site in a clean module",
            {"clean_body": "pub fn g(x: Option<u8>) -> u8 {\n    x.expect(\"held\")\n}\n"},
            "demo::clean: 1 site(s) of expect_used that nothing allows",
        ),
        (
            "a site the row does not list",
            {"debt_body": "pub fn f(x: Option<u8>) -> u8 {\n    x.unwrap() + 1\n}\n"
                          "pub fn h() {\n    unreachable!()\n}\n"},
            "demo::debt: 1 site(s) of unreachable that nothing allows",
        ),
        (
            "a listed lint with no site left",
            {"debt_body": "pub fn f(x: Option<u8>) -> u8 {\n    x.unwrap_or(0) + 1\n}\n"},
            "the row lists unwrap_used and the module has no site of it left",
        ),
        (
            "an id past the last one given",
            {"rows": "| TD-003 | `demo` | `debt` | `unwrap_used`, `arithmetic_side_effects` |\n",
             "debt_comment": "// Totality debt TD-003 (docs/c-abi-architecture.md section 7).\n"},
            "past TD-002",
        ),
        (
            "cells above the ratchet",
            {"debt_attr": "#[allow(clippy::indexing_slicing, clippy::unwrap_used, "
                          "clippy::arithmetic_side_effects)]\n",
             "rows": "| TD-001 | `demo` | `debt` | `indexing_slicing`, `unwrap_used`, "
                     "`arithmetic_side_effects` |\n"},
            "above the 2 the ratchet holds",
        ),
        (
            "cells below the ratchet",
            {"debt_attr": "#[allow(clippy::unwrap_used)]\n",
             "rows": "| TD-001 | `demo` | `debt` | `unwrap_used` |\n"},
            "lower CELLS to 1",
        ),
    ]
    for name, kwargs, want in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _fixture(root, **kwargs)
            try:
                findings, _, _ = grade(root, ("demo",), 2, 2)
            except InputError as e:
                failures.append(f"{name}: cannot grade: {e}")
                continue
        if want is None:
            if findings:
                failures.append(f"{name}: want no finding, got {findings}")
        elif not any(want in finding for finding in findings):
            failures.append(f"{name}: want a finding carrying {want!r}, got {findings}")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        # A generated module is read for unlisted sites only: its listed lint stands.
        _fixture(
            root,
            lib_extra="// Totality debt TD-002 (docs/c-abi-architecture.md section 7).\n"
                      "#[allow(clippy::panic)]\n" + gen,
            rows="| TD-001 | `demo` | `debt` | `unwrap_used`, `arithmetic_side_effects` |\n"
                 "| TD-002 | `demo` | `sm` | `panic` |\n",
        )
        findings, rows, total = grade(root, ("demo",), 2, 3)
        if findings or (rows, total) != (2, 3):
            failures.append(f"a generated module: want no finding over 2 rows of 3 cells, got "
                            f"{findings}, {rows}, {total}")
        (root / REGISTER).unlink()
        try:
            grade(root, ("demo",), 2, 3)
            failures.append("a tree without its register is graded")
        except InputError:
            pass

    for crate in CRATES:
        if not (REPO_ROOT / "crates" / crate / "src" / "lib.rs").is_file():
            failures.append(f"CRATES names {crate}, which has no crate root")

    if failures:
        for line in failures:
            print(f"totality-debt: SELFTEST FAIL -- {line}", file=sys.stderr)
        return 1
    print(f"totality-debt: selftest OK -- {len(cases)} fixture cases and the refused inputs")
    return 0


def main(argv: list[str]) -> int:
    modes = {"--check": check, "--selftest": selftest}
    if len(argv) != 2 or argv[1] not in modes:
        print(
            "usage: totality_debt_gate.py --check | --selftest "
            "(a mode is required; there is no default)",
            file=sys.stderr,
        )
        return 2
    return modes[argv[1]]()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
