#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4557 (no register item) -- a table reads its limit from the snapshot its creator hands it,
never from the build, except to size its storage.

The citation is `no register item`: this gate holds a design rule of the limits plane Round 4557
declared (`crates/wz-session-core/src/limits.rs`, "Who reads a value"), not a register item. It
is `policy_read_gate.py`'s rule for the limits, and shares its reader of items.

## The rule

A limit a stage after the build may decide (a bound or a parameter: every limit the generated
module `limits_generated.rs` gives a `LimitSpec`) is a field of a snapshot, `SessionLimits` or
`RuntimeLimits`. A creator resolves the snapshot once and hands it to the machines it creates; a
machine reads the limit through the snapshot and never from the build, so a value a later stage
states reaches every table of the scope.

The build's constant, `caps::<LIMIT>`, keeps one use: sizing storage only the build can size, a
const-generic argument or an array length. Every other read of it is refused, unless it is at a
site `ALLOWED` lists with the reason it may read the build, or the limit is one whose readers have
not moved to the snapshot yet. Which limits those are is declared once, by each `[[limit]]` of
`deploy/wz-config.toml` (`read = "build"`), read here through `wz_config.py`'s loader; the same
declaration makes the reader of a document refuse a statement of such a limit by name. The
declaration and `ALLOWED` are the debt: a listed site that no longer reads the build is refused,
and the declaration is held to the code both ways (a limit declared read from the build whose
snapshot field production code reads has moved, and a limit declared read from the snapshot whose
field nothing reads has not), so both shrink with the code and never claim a read that is gone.

A read of a snapshot's field counts as a machine reading the limit only where the snapshot is the
one its creator resolved. A site that builds a snapshot of its own from another statement (the
environment) and reads it back moves no limit, and is listed in `OWN_SNAPSHOTS` with the reason.

## What a read is

Outside a comment and a string literal, a path that ends in `caps::<LIMIT>` (`caps::`,
`crate::caps::`, `wz_session_core::caps::`), and a `use` that imports `<LIMIT>` from `caps`
(`caps::{.., <LIMIT>, ..}`), which the gate cannot follow to its uses and so counts as a read at
the import. A read is storage, and free, when it is:

  * an array's length: after the `;` of the innermost `[..]` (`[T; caps::X]`, `[v; caps::X]`);
  * a const-generic argument: in a `{ .. }` block that is an argument of a generic list
    (`BoundedVec<T, { caps::X }>`, `Foo::<{ caps::X }>`).

What this cannot see, stated rather than implied: a constant renamed by `use .. as ..`, a `const`
item that copies the build's value and is then read (the copy is the read, at the `const`), and a
`caps` module reached by another name.

## The population

Every `.rs` file under `crates/`, minus the definitions (`caps.rs`, `caps_generated.rs`,
`caps_binding_generated.rs` and `limits_generated.rs`), a crate's integration tests
(`crates/<crate>/tests/`), and every item and module file that exists only in a test build, read
by `subsystem_spawn_gate`'s reader as `policy_read_gate.py` reads it.

Usage:
    python3 scripts/lib/limit_read_gate.py --check
    python3 scripts/lib/limit_read_gate.py --selftest
    python3 scripts/lib/limit_read_gate.py --list [LIMIT]
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rust_comments  # noqa: E402  -- after the path insert that finds it
import wz_config  # noqa: E402  (the one declaration, and its loader)
from policy_read_gate import enclosing_item, is_integration_test, item_spans, sources  # noqa: E402
from subsystem_spawn_gate import cfg_test_files, cfg_test_spans  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The generated module, relative to the root: every limit with a snapshot field.
GENERATED = Path("crates/wz-session-core/src/limits_generated.rs")

#: The definitions of the build's values, which the gate does not read.
DEFINITIONS = frozenset(
    {
        GENERATED,
        Path("crates/wz-session-core/src/caps.rs"),
        Path("crates/wz-session-core/src/caps_generated.rs"),
        Path("crates/wz-session-core/src/caps_binding_generated.rs"),
    }
)

#: Each limit's name, as the generated module declares it.
LIMIT_RE = re.compile(r"const LIMIT: &'static str = \"([A-Z][A-Z0-9_]*)\";")

NOT_MOVED = "no machine reads its snapshot field yet; its readers move to the snapshot bound by bound"


def declared_pending(decl: dict) -> dict[str, str]:
    """The limits the declaration states no machine reads from the snapshot yet (`read =
    "build"`), each with the reason. A limit is declared read from the snapshot in the change
    that moves its readers, and the gate holds it to every read from then on. A bound whose
    constant only sizes storage is declared read from the build all the same: on a growable table
    it enforces nothing until the table asks the snapshot's quota."""
    return {
        lim["id"]: NOT_MOVED
        for lim in wz_config.open_limits(decl)
        if lim["read"] == wz_config.LIMIT_READ_BUILD
    }


#: (path pattern relative to the root, innermost item, reason): a read of a moved limit that may
#: stay a read of the build. One line per allowed site.
ALLOWED: tuple[tuple[str, str, str], ...] = (
    ("crates/wz-session-core/src/pubsub.rs", "_", "a build-time assertion on the storage the constant sizes: a fixed table's rows fit the u16 positions of the match cache"),
    ("crates/wz-session-core/src/lent_control.rs", "NAMED_KEYEXPR_BYTES", "the length of the body array a NamedKeyexpr holds (header, widest id, a key of the build's capacity); the constructor refuses past the session's quota, which the domain keeps at most that capacity"),
)

#: (path pattern relative to the root, innermost item, reason): a site that reads a snapshot it
#: built itself from another statement than its creator's, so its read moves no limit. One line per
#: site.
OWN_SNAPSHOTS: tuple[tuple[str, str, str], ...] = (
    ("crates/wz-node-time/src/node_clock.rs", "max_delta_from", "the clock selects UHLC_MAX_DELTA_MS from the environment into a RuntimeLimits of its own and reads it back; the node's resolved snapshot does not reach it"),
)

#: A path that ends in `caps::<NAME>`.
READ_RE = re.compile(r"(?<![\w])caps\s*::\s*(?P<name>[A-Z][A-Z0-9_]*)\b")
#: A `use` group under `caps`: `caps::{A, B as C, ..}`.
GROUP_RE = re.compile(r"(?<![\w])caps\s*::\s*\{(?P<body>[^{}]*)\}")
NAME_RE = re.compile(r"\b[A-Z][A-Z0-9_]*\b")

OPENERS = {"(": ")", "[": "]", "{": "}"}
CLOSERS = {v: k for k, v in OPENERS.items()}


def limits(root: Path) -> list[str]:
    """Every limit with a snapshot field, as the generated module declares it."""
    path = root / GENERATED
    if not path.is_file():
        raise SystemExit(f"limit-read FAIL: {GENERATED} is not there; the gate has no limit to read")
    names = sorted(set(LIMIT_RE.findall(path.read_text(encoding="utf-8"))))
    if not names:
        raise SystemExit(f"limit-read FAIL: {GENERATED} declares no limit")
    return names


def _innermost_open(text: str, pos: int) -> int:
    """The index of the innermost `(`, `[` or `{` open at `pos`, or -1."""
    stack: list[int] = []
    for i in range(pos):
        ch = text[i]
        if ch in OPENERS:
            stack.append(i)
        elif ch in CLOSERS and stack:
            stack.pop()
    return stack[-1] if stack else -1


def _in_generic_list(text: str, brace: int) -> bool:
    """Whether the `{` at `brace` is an argument of a generic list: back from it, at its own
    bracket depth, an unclosed `<` comes before the bracket or statement that holds it.

    A generic list's brackets are told from the comparison operators by their spacing, which
    `cargo fmt --check` holds every crate to: a list's `<` follows a name or `::` with no space
    (`BoundedVec<`, `::<`) and its `>` follows no space, while an operator stands between
    spaces."""
    depth = 0
    angle = 0
    i = brace - 1
    while i >= 0:
        ch = text[i]
        if ch in CLOSERS:
            depth += 1
        elif ch in OPENERS:
            if depth == 0:
                return False
            depth -= 1
        elif depth == 0:
            if ch == ";":
                return False
            prev = text[i - 1] if i > 0 else " "
            if ch == ">" and not prev.isspace() and prev not in "-=>":
                angle += 1
            elif ch == "<" and (prev.isalnum() or prev in "_:"):
                if angle == 0:
                    return True
                angle -= 1
        i -= 1
    return False


def is_storage(text: str, pos: int) -> bool:
    """Whether the read at `pos` sizes storage: an array's length or a const-generic argument."""
    open_at = _innermost_open(text, pos)
    if open_at < 0:
        return False
    opener = text[open_at]
    if opener == "[":
        return _has_top_level_semicolon(text, open_at + 1, pos)
    if opener == "{":
        if _in_generic_list(text, open_at):
            return True
        outer = _innermost_open(text, open_at)
        return outer >= 0 and text[outer] == "[" and _has_top_level_semicolon(text, outer + 1, open_at)
    return False


def _has_top_level_semicolon(text: str, start: int, end: int) -> bool:
    depth = 0
    for i in range(start, end):
        ch = text[i]
        if ch in OPENERS:
            depth += 1
        elif ch in CLOSERS:
            depth -= 1
        elif ch == ";" and depth == 0:
            return True
    return False


def production(root: Path) -> list[tuple[Path, str, list[tuple[int, int]]]]:
    """Every production source: (path relative to the root, text with comments and literals
    blank, the spans of its test-only items)."""
    all_sources = sources(root)
    test_only = cfg_test_files(all_sources)
    out: list[tuple[Path, str, list[tuple[int, int]]]] = []
    for path in all_sources:
        rel = path.relative_to(root)
        if rel in DEFINITIONS or is_integration_test(rel) or path.resolve() in test_only:
            continue
        stripped = rust_comments.strip_comments(path.read_text(encoding="utf-8", errors="replace"), blank_literals=True)
        out.append((rel, stripped, cfg_test_spans(stripped)))
    return out


#: A call of a snapshot's accessor: `.<field>()` or `.<field>_held()`.
ACCESSOR_RE = re.compile(r"\.\s*(?P<field>[a-z][a-z0-9_]*?)(?:_held)?\s*\(\s*\)")


def snapshot_reads(
    root: Path,
    own: tuple[tuple[str, str, str], ...],
) -> tuple[dict[str, str], set[tuple[str, str]]]:
    """Each limit whose snapshot field production code reads, with the first site: the field is
    the limit's name in lower case, read through its accessor. A read at a site `own` lists reads
    a snapshot of the site's own and is left out; the second value is the listed sites a read was
    found at."""
    fields = {name.lower(): name for name in limits(root)}
    found: dict[str, str] = {}
    used: set[tuple[str, str]] = set()
    for rel, stripped, skip in production(root):
        path = rel.as_posix()
        spans: list[tuple[int, int, str]] | None = None
        for m in ACCESSOR_RE.finditer(stripped):
            name = fields.get(m.group("field"))
            if name is None or any(a <= m.start() <= b for a, b in skip):
                continue
            if spans is None:
                spans = item_spans(stripped)
            item = enclosing_item(spans, m.start())
            entry = next((e for e in own if allows(e, path, item)), None)
            if entry is not None:
                used.add((entry[0], entry[1]))
                continue
            if name not in found:
                found[name] = f"{path}:{stripped.count(chr(10), 0, m.start()) + 1}"
    return found, used


def reads(root: Path) -> list[tuple[str, int, str, str]]:
    """Every read of a limit's build value in production code, storage left out:
    (path, line, item, limit)."""
    names = set(limits(root))
    found: list[tuple[str, int, str, str]] = []
    for rel, stripped, skip in production(root):
        if "caps" not in stripped:
            continue
        hits: list[tuple[int, str]] = [
            (m.start(), m.group("name")) for m in READ_RE.finditer(stripped) if m.group("name") in names
        ]
        for group in GROUP_RE.finditer(stripped):
            body_at = group.start("body")
            for n in NAME_RE.finditer(group.group("body")):
                if n.group(0) in names:
                    hits.append((body_at + n.start(), n.group(0)))
        if not hits:
            continue
        spans = item_spans(stripped)
        for at, name in hits:
            if any(a <= at <= b for a, b in skip) or is_storage(stripped, at):
                continue
            line = stripped.count("\n", 0, at) + 1
            found.append((rel.as_posix(), line, enclosing_item(spans, at), name))
    return sorted(found)


def allows(entry: tuple[str, str, str], path: str, item: str) -> bool:
    pattern, entry_item, _ = entry
    return fnmatch.fnmatchcase(path, pattern) and entry_item in ("*", item)


def is_exact(entry: tuple[str, str, str]) -> bool:
    """Whether `entry` names one site, and so is stale when no read is there."""
    return "*" not in entry[0] and entry[1] != "*"


def check(
    root: Path,
    pending: dict[str, str],
    allowed: tuple[tuple[str, str, str], ...],
    own: tuple[tuple[str, str, str], ...],
) -> tuple[list[str], int]:
    """The findings over `root` against `pending` (the limits declared read from the build),
    `allowed` and `own`, and how many reads were found."""
    findings: list[str] = []
    known = set(limits(root))
    for name, reason in sorted(pending.items()):
        if name not in known:
            findings.append(
                f"the declaration says {name} is read from the build, and {GENERATED} gives it "
                f"no snapshot field; regenerate it (`wz_config.py --write`)"
            )
        if not reason.strip():
            findings.append(f"the pending limit {name} states no reason")
    for kind, entries in (("allowed", allowed), ("own-snapshot", own)):
        seen: set[tuple[str, str]] = set()
        for entry in entries:
            key = (entry[0], entry[1])
            if not entry[2].strip():
                findings.append(f"the {kind} site {entry[0]} :: {entry[1]} states no reason")
            if key in seen:
                findings.append(f"the {kind} site {entry[0]} :: {entry[1]} is listed twice")
            seen.add(key)
    found = reads(root)
    used: set[tuple[str, str]] = set()
    for path, line, item, name in found:
        if name in pending:
            continue
        entry = next((e for e in allowed if allows(e, path, item)), None)
        if entry is None:
            findings.append(
                f"{path}:{line} reads the build's {name} in `{item}`; a table reads the "
                f"snapshot its creator hands it (`SessionLimits` / `RuntimeLimits`) and the "
                f"build only to size storage. Take the limit from the creator, or list the "
                f"site in ALLOWED with the reason it may read the build"
            )
        else:
            used.add((entry[0], entry[1]))
    moved, own_used = snapshot_reads(root, own)
    for name in sorted(set(pending) & set(moved)):
        findings.append(
            f"the limit {name} is declared `read = \"build\"` ({pending[name]}), and production "
            f"code reads it from the snapshot ({moved[name]}); its readers have moved, so declare "
            f"it `read = \"snapshot\"` in {wz_config.DECL.relative_to(wz_config.ROOT)} and the "
            f"gate holds its every read"
        )
    for name in sorted(known - set(pending) - set(moved)):
        findings.append(
            f"no machine reads the snapshot field of {name} (`.{name.lower()}()` or "
            f"`.{name.lower()}_held()`), so its readers have not moved; declare it "
            f"`read = \"build\"` in {wz_config.DECL.relative_to(wz_config.ROOT)}"
        )
    for entry in allowed:
        if is_exact(entry) and (entry[0], entry[1]) not in used:
            findings.append(
                f"the allowed site {entry[0]} :: {entry[1]} reads the build no longer; "
                f"take it off ALLOWED"
            )
    for entry in own:
        if is_exact(entry) and (entry[0], entry[1]) not in own_used:
            findings.append(
                f"the own-snapshot site {entry[0]} :: {entry[1]} reads no snapshot field; "
                f"take it off OWN_SNAPSHOTS"
            )
    return findings, len(found)


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def selftest() -> int:
    """Drive every rule over a fixture tree, in both directions."""
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root, GENERATED.as_posix(),
               "impl LimitSpec for A { const LIMIT: &'static str = \"MOVED\"; }\n"
               "impl LimitSpec for B { const LIMIT: &'static str = \"WAITING\"; }\n"
               "impl LimitSpec for C { const LIMIT: &'static str = \"DONE\"; }\n"
               "const X: usize = caps::MOVED;\n")
        _write(root, "crates/wz-session-core/src/caps.rs", "pub const MOVED: usize = 4;\n")
        _write(root, "crates/a/src/lib.rs",
               "pub struct Table {\n    v: BoundedVec<u8, { caps::MOVED }, P>,\n"
               "    a: [u8; caps::MOVED],\n    b: [u8; { caps::DONE }],\n}\n"
               "pub fn turbo() -> usize {\n    Foo::<{ crate::caps::MOVED }>::new().len()\n}\n"
               "pub fn fill() -> [u8; 4] {\n    [0; caps::MOVED]\n}\n"
               "pub fn machine(n: usize) -> bool {\n    n < caps::MOVED\n}\n"
               "pub fn call(n: usize) -> usize {\n    f(n, { caps::MOVED })\n}\n"
               "pub fn indexed(v: &[u8]) -> u8 {\n    v[caps::MOVED - 1]\n}\n"
               "pub fn compared(n: usize) -> bool {\n    n < 2 && {\n        caps::MOVED > n\n    }\n}\n"
               "pub fn creator() -> usize {\n    wz_session_core::caps::MOVED\n}\n"
               "use crate::caps::{OTHER, MOVED as M};\n"
               "pub fn waiting() -> usize {\n    caps::WAITING\n}\n"
               "pub fn capacity() -> usize {\n    caps::OTHER\n}\n"
               "pub fn table(limits: &SessionLimits) -> Quota {\n    limits.moved_held()\n}\n"
               "pub fn parameter(limits: &SessionLimits) -> usize {\n    limits.done()\n}\n"
               "pub fn from_env(n: usize) -> usize {\n    let mut own = SessionLimits::defaults();\n"
               "    own.select_waiting(n);\n    own.waiting()\n}\n"
               "// limits.waiting() and caps::MOVED in a comment are prose.\n"
               "pub fn quoted() -> &'static str {\n    \"caps::MOVED\"\n}\n"
               "#[cfg(test)]\nmod tests {\n    fn t() { let _ = caps::MOVED; limits.waiting(); }\n}\n")
        _write(root, "crates/a/tests/it.rs", "fn t() { let _ = caps::MOVED; }\n")

        found = reads(root)
        got = {(path, item, name) for path, _, item, name in found}
        want = {
            ("crates/a/src/lib.rs", "machine", "MOVED"),
            ("crates/a/src/lib.rs", "call", "MOVED"),
            ("crates/a/src/lib.rs", "indexed", "MOVED"),
            ("crates/a/src/lib.rs", "compared", "MOVED"),
            ("crates/a/src/lib.rs", "creator", "MOVED"),
            ("crates/a/src/lib.rs", "<module>", "MOVED"),
            ("crates/a/src/lib.rs", "waiting", "WAITING"),
        }
        if got != want:
            failures.append(f"reads found {sorted(got)}, want {sorted(want)}")
        if len(found) != len(want):
            failures.append(f"{len(found)} reads found, want {len(want)}: one each")

        pending = {"WAITING": "not moved"}
        allowed = (
            ("crates/a/src/lib.rs", "creator", "a creator"),
            ("crates/a/src/lib.rs", "<module>", "an import"),
            ("crates/a/src/lib.rs", "call", "a call"),
            ("crates/a/src/lib.rs", "indexed", "an index"),
            ("crates/a/src/lib.rs", "compared", "a block"),
        )
        own = (("crates/a/src/lib.rs", "from_env", "a snapshot of its own, read back"),)
        findings, _ = check(root, pending, allowed, own)
        refused = [f for f in findings if "reads the build's" in f]
        if len(refused) != 1 or "`machine`" not in refused[0]:
            failures.append(f"the one unlisted machine is refused, got {findings}")
        if len(findings) != 1:
            failures.append(f"a pending limit's read is allowed, got {findings}")

        findings, _ = check(root, {**pending, "DONE": "moved already"}, allowed, own)
        if not any("limit DONE is declared `read = \"build\"` (moved already)" in f for f in findings):
            failures.append(f"a pending limit whose snapshot field is read is stale, got {findings}")

        # WAITING's field is read in a comment, in a test and in a snapshot of a site's own: it
        # has not moved.
        findings, _ = check(root, {}, allowed, own)
        if not any("snapshot field of WAITING" in f for f in findings):
            failures.append(f"a limit declared read whose field nothing reads is refused, got {findings}")
        if any("snapshot field of MOVED" in f or "snapshot field of DONE" in f for f in findings):
            failures.append(f"a limit whose field is read is not refused as unmoved, got {findings}")

        # Unlisted, the site's read of its own snapshot reads as a machine's.
        findings, _ = check(root, pending, allowed, ())
        if not any("limit WAITING is declared" in f and "(crates/a/src/lib.rs:" in f for f in findings):
            failures.append(f"a read of a snapshot no site lists moves the limit, got {findings}")

        findings, _ = check(root, {**pending, "NOPE": "a typo"}, allowed, own)
        if not any("says NOPE is read from the build" in f for f in findings):
            failures.append(f"a pending name that is no limit is refused, got {findings}")

        stale = allowed + (("crates/a/src/lib.rs", "gone", "a creator that left"),)
        findings, _ = check(root, pending, stale, own)
        if not any("gone reads the build no longer" in f for f in findings):
            failures.append(f"a listed site with no read is stale, got {findings}")

        stale_own = own + (("crates/a/src/lib.rs", "gone", "a site that left"),)
        findings, _ = check(root, pending, allowed, stale_own)
        if not any("own-snapshot site crates/a/src/lib.rs :: gone reads no snapshot field" in f
                   for f in findings):
            failures.append(f"a listed own-snapshot site with no read is stale, got {findings}")

        bad = (("crates/a/src/lib.rs", "creator", " "), ("crates/a/src/lib.rs", "creator", "twice"))
        findings, _ = check(root, pending, bad + allowed[1:], own)
        if not any("states no reason" in f for f in findings) or not any("listed twice" in f for f in findings):
            failures.append(f"an entry with no reason and a duplicate are refused, got {findings}")

    # The declaration's pending set: every limit a later stage decides that is read from the build.
    decl = {"limits": [
        {"id": "A", "storage": "both", "read": "snapshot"},
        {"id": "B", "storage": "quota", "read": "build"},
        {"id": "C", "storage": "capacity"},
    ]}
    if declared_pending(decl) != {"B": NOT_MOVED}:
        failures.append(f"the pending set is the limits declared read from the build, got {declared_pending(decl)}")

    # The real lists: each limit declared read from the build is a limit, and each listed site
    # names a file.
    known = set(limits(REPO_ROOT))
    for name in declared_pending(wz_config.load_decl()):
        if name not in known:
            failures.append(f"the declaration names {name}, which is no limit with a snapshot field")
    for kind, entries in (("ALLOWED", ALLOWED), ("OWN_SNAPSHOTS", OWN_SNAPSHOTS)):
        for pattern, item, reason in entries:
            if "*" not in pattern and not (REPO_ROOT / pattern).is_file():
                failures.append(f"{kind} names {pattern}, which is not a file")
            if not reason.strip() or not item:
                failures.append(f"{kind} entry {pattern} :: {item} is incomplete")

    if failures:
        for line in failures:
            print(f"  limit-read SELFTEST FAIL: {line}", file=sys.stderr)
        return 1
    print("  limit-read: selftest OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="hold the crates to the declaration, ALLOWED and OWN_SNAPSHOTS")
    ap.add_argument("--selftest", action="store_true", help="drive every rule over a fixture tree")
    ap.add_argument("--list", nargs="?", const="", metavar="LIMIT",
                    help="print every read outside storage, of LIMIT or of every limit")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.list is not None:
        for path, line, item, name in reads(REPO_ROOT):
            if not args.list or name == args.list:
                print(f"{path}:{line}: {name} in `{item}`")
        return 0
    if not args.check:
        ap.error("state --check, --selftest or --list")
    pending = declared_pending(wz_config.load_decl())
    findings, count = check(REPO_ROOT, pending, ALLOWED, OWN_SNAPSHOTS)
    if findings:
        print("limit-read FAIL:", file=sys.stderr)
        for line in findings:
            print(f"  - {line}", file=sys.stderr)
        return 1
    moved = len(limits(REPO_ROOT)) - len(pending)
    print(
        f"  limit-read: {count} read(s) of the build outside storage; {moved} limit(s) read from "
        f"the snapshot, {len(pending)} declared read from the build ({NOT_MOVED}), "
        f"{len(ALLOWED)} allowed site(s), {len(OWN_SNAPSHOTS)} own-snapshot site(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
