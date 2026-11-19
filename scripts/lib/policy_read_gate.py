#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4517 (no register item) -- a machine reads a policy from the snapshot it is handed, never
from the build.

The citation is `no register item`: this gate holds a design rule of the policy plane
(`crates/wz-session-core/src/policy.rs`, "Who reads a value"), not a register item.

## The rule

A policy's value is a `SessionPolicy`, a snapshot. A creator -- a runtime, a session, a link, an
entity -- resolves the snapshot of its scope once, starting from the build defaults
(`SessionPolicy::defaults`), and hands it to the machines it creates. A machine reads a policy
through the snapshot it holds and never from the build, so a value a later stage selects reaches
every machine of the scope, and two sessions of one process can hold two values.

A read of the build defaults is therefore a claim to be a creator. This gate makes the claim
explicit: every such read in the crates' production code is either at a site listed in
`ALLOWED`, each with the reason it may read the build, or it is refused. A listed site that no
longer reads the build is refused too, so the list shrinks with the code and never claims a
creator that is gone.

## What a read of the build is

Any of, outside a comment and a string literal:

  * `SessionPolicy::from_build()`, `SessionPolicy::defaults()`, `SessionPolicy::default()`;
  * `<Policy>::default()` and `<Policy>::stated()` of a policy's value type;
  * `<SessionPolicy as Default>::default()` and the same of a value type;
  * a struct that derives `Default` and has a field of `SessionPolicy` or of a value type: its
    `default()`, and every `..Default::default()` and derived `Default` built on it, take the
    build's value, so the read is placed at the struct (step 3c);
  * `<field>: Default::default()` where some struct gives `<field>` such a type: the compiler
    infers the value type, so the read is placed where it is written (step 3c).

The value types are read from the generated module (`policy_generated.rs`, `pub enum <Name>`),
never listed here, so a policy the declaration adds is in the population the moment it exists.

What this cannot see, stated rather than implied: a value type renamed by `use .. as ..`, an
inferred `Default::default()` that is not a field initializer (a `let` or an argument), and a
hand-written `impl Default` that reaches the build through a call the patterns above do not
name. Each is a read of the build the gate does not name.

## The population

Every `.rs` file under `crates/`, minus:

  * the generated module, which is where the build defaults are defined;
  * a crate's integration tests (`crates/<crate>/tests/`);
  * every item and every module file that exists only in a test build (`#[cfg(test)]`,
    `#[cfg(all(test, ..))]`), read by `subsystem_spawn_gate`'s reader so the two gates agree on
    what test code is.

A test is free to read the build: it asserts what the build states.

## Where a site is

A site is a file and the innermost item the read is in: a `fn`, a `const` or `static`, or a
`type`. Several reads in one item are one site. A path pattern with `*` and the item `*` allow a
whole family of files; such an entry is never reported stale.

Usage:
    python3 scripts/lib/policy_read_gate.py --check
    python3 scripts/lib/policy_read_gate.py --selftest
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rust_comments  # noqa: E402  -- after the path insert that finds it
from subsystem_spawn_gate import cfg_test_files, cfg_test_spans  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The generated module, relative to the root: it defines the build defaults.
GENERATED = Path("crates/wz-session-core/src/policy_generated.rs")

#: Each policy's value type, as the generated module declares it.
POLICY_TYPE_RE = re.compile(r"^pub enum ([A-Z][A-Za-z0-9]*) \{", re.M)

STEP_3B = "a creator outside session-core: it is handed a snapshot in step 3b"
WRAPPER = "the build-default wrapper of a call that takes a snapshot; it goes when its callers move"

#: (path pattern relative to the root, innermost item, reason). One line per allowed site.
ALLOWED: tuple[tuple[str, str, str], ...] = (
    # The policy plane itself.
    ("crates/wz-session-core/src/policy*.rs", "*", "the policy plane, which defines the build defaults"),
    # Session-core: the key gate's reads of the build.
    ("crates/wz-session-core/src/key_gate.rs", "of_build", "the gate a registry starts from; the session hands its own in step 3b"),
    ("crates/wz-session-core/src/key_gate_open.rs", "of_build", "the build-time refusal of a closed default without the feature"),
    # Outside session-core: every site that still reads the build.
    ("crates/wz-ap-demo/src/args.rs", "resolve_policy", "creator: resolves the snapshot (build defaults until a run-time document is read)"),
    ("crates/wz-capi-coop/src/engine.rs", "resolve_policy", "creator: resolves the snapshot (build defaults until a run-time document is read)"),
    ("crates/wz-capi-core/src/open_plan.rs", "resolve_policy", "creator: resolves the snapshot (build defaults until a run-time document is read)"),
    ("crates/wz-capi-pico/src/session.rs", "resolve_policy", "creator: resolves the snapshot (build defaults until a run-time document is read)"),
    ("crates/wz-capi-port/src/observation/supervision.rs", "resolve_policy", "creator: resolves the snapshot (build defaults until a run-time document is read)"),
    ("crates/wz-mcu-multicast-e2e/src/lib.rs", "resolve_policy", "creator: resolves the snapshot (build defaults until a run-time document is read)"),
    ("crates/wz-mcu-session-acceptor/src/lib.rs", "resolve_policy", "creator: resolves the snapshot (build defaults until a run-time document is read)"),
    ("crates/wz-mesh-client/src/lib.rs", "resolve_policy", "creator: resolves the snapshot (build defaults until a run-time document is read)"),
    ("crates/wz-node-time/src/event_log.rs", "resolve_policy", "creator: resolves the snapshot (build defaults until a run-time document is read)"),
    ("crates/wz-replay/src/live.rs", "resolve_policy", "creator: resolves the snapshot (build defaults until a run-time document is read)"),
    ("crates/wz-runtime-tokio-test-support/src/lib.rs", "fixture_policy", "creator: resolves the snapshot (build defaults until a run-time document is read); a test fixture"),
    ("crates/wz-runtime-tokio/src/router_forward.rs", "resolve_policy", "creator: resolves the snapshot (build defaults until a run-time document is read)"),
)

#: The items a read can be in. A `const fn` is a `fn`; `const` and `static` are named by the
#: identifier before their `:`.
ITEM_RE = re.compile(
    r"\bfn\s+(?P<fn>[A-Za-z_]\w*)"
    r"|\b(?:const|static)\s+(?:mut\s+)?(?!fn\b)(?P<value>[A-Za-z_]\w*)\s*:"
    r"|\btype\s+(?P<alias>[A-Za-z_]\w*)\b"
)


def policy_types(root: Path) -> list[str]:
    """Every policy's value type, as the generated module declares it."""
    path = root / GENERATED
    if not path.is_file():
        raise SystemExit(f"policy-read FAIL: {GENERATED} is not there; the gate has no policy to read")
    types = sorted(set(POLICY_TYPE_RE.findall(path.read_text(encoding="utf-8"))))
    if not types:
        raise SystemExit(f"policy-read FAIL: {GENERATED} declares no policy value type")
    return types


def read_re(types: list[str]) -> re.Pattern[str]:
    """A read of the build defaults, of `SessionPolicy` or of one of `types`."""
    alt = "|".join(re.escape(t) for t in types)
    default_of = r"<\s*(?:[\w:]*::)?(?:SessionPolicy|" + alt + r")\s+as\s+(?:[\w:]*::)?Default\s*>\s*::\s*default"
    return re.compile(
        r"(?<![\w])SessionPolicy\s*::\s*(?:from_build|defaults|default)\s*\(\s*\)"
        r"|(?<![\w])(?:" + alt + r")\s*::\s*(?:default|stated)\s*\(\s*\)"
        r"|" + default_of + r"\s*\(\s*\)"
    )


def brace_pairs(text: str) -> dict[int, int]:
    """The index of the `}` closing each `{`, for text whose comments and literals are blank."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for i, ch in enumerate(text):
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            pairs[stack.pop()] = i
    return pairs


def _scan_to(text: str, start: int, pairs: dict[int, int], stop: str) -> int:
    """The index of the first `stop` character after `start` outside brackets, braces skipped
    whole; `len(text)` when there is none."""
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch == "{":
            if stop == "{" and depth == 0:
                return i
            i = pairs.get(i, len(text) - 1) + 1
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == ";" and depth == 0:
            return i if stop == ";" else -1
        i += 1
    return len(text) if stop == ";" else -1


def item_spans(text: str) -> list[tuple[int, int, str]]:
    """Every item of `text` with the span it covers: a `fn` to its body's closing brace, a
    `const`, `static` or `type` to its `;`. A `fn` with no body covers nothing."""
    pairs = brace_pairs(text)
    spans: list[tuple[int, int, str]] = []
    for m in ITEM_RE.finditer(text):
        before = m.start() - 1
        while before >= 0 and text[before].isspace():
            before -= 1
        # A const generic parameter (`<const N: usize>`) and a `'static` lifetime are no item.
        if m.group("value") and before >= 0 and text[before] in "<,'":
            continue
        if m.group("fn"):
            body = _scan_to(text, m.end(), pairs, "{")
            if body < 0:
                continue
            spans.append((m.start(), pairs.get(body, len(text)), m.group("fn")))
        else:
            spans.append((m.start(), _scan_to(text, m.end(), pairs, ";"), m.group("value") or m.group("alias")))
    return spans


def enclosing_item(spans: list[tuple[int, int, str]], pos: int) -> str:
    """The innermost item whose span holds `pos`, or `<module>`."""
    best: tuple[int, int, str] | None = None
    for start, end, name in spans:
        if start <= pos <= end and (best is None or start > best[0]):
            best = (start, end, name)
    return best[2] if best else "<module>"


def sources(root: Path) -> list[Path]:
    """Every `.rs` file under `root/crates`, build output left out."""
    out: list[Path] = []
    for base, dirs, files in os.walk(root / "crates"):
        dirs[:] = sorted(d for d in dirs if d not in ("target", ".git"))
        out += [Path(base) / name for name in files if name.endswith(".rs")]
    return sorted(out)


def is_integration_test(rel: Path) -> bool:
    """Whether `rel` is under a crate's `tests/`, the integration tests cargo builds."""
    parts = rel.parts
    return len(parts) > 3 and parts[0] == "crates" and parts[2] == "tests"


#: A struct definition: its attributes, its name and the bracket its fields open with.
STRUCT_RE = re.compile(
    r"(?P<attrs>(?:#\s*\[[^\]]*\]\s*)*)"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?struct\s+(?P<name>[A-Za-z_]\w*)\s*(?:<[^>{(;]*>\s*)?"
    r"(?:where[^{;]*)?(?P<open>[{(])"
)
DERIVES_DEFAULT_RE = re.compile(r"#\s*\[\s*derive\s*\([^\]]*\bDefault\b[^\]]*\)\s*\]")
FIELD_ATTR_RE = re.compile(r"#\s*\[[^\]]*\]")
#: A field set from the `Default` of a type the compiler infers: `name: Default::default()`.
INFERRED_RE = re.compile(r"(?<![\w.])(?P<field>[a-z_]\w*)\s*:\s*(?:core::default::|std::default::)?Default\s*::\s*default\s*\(\s*\)")


def _split_top(body: str) -> list[str]:
    """`body` split at the commas outside any bracket."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for i, ch in enumerate(body):
        if ch in "<([{":
            depth += 1
        elif ch in ")]}" or (ch == ">" and (i == 0 or body[i - 1] != "-")):
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _last_segment(ty: str) -> str:
    """The type a field names, without its path: `crate::policy::KeySet` is `KeySet`."""
    return ty.strip().split("::")[-1].strip()


def struct_fields(stripped: str) -> list[tuple[int, str, bool, list[tuple[str, str]]]]:
    """Every struct of `stripped`: (offset, name, whether it derives `Default`, [(field, type)]).
    A tuple struct's fields are named by their position."""
    pairs = brace_pairs(stripped)
    out: list[tuple[int, str, bool, list[tuple[str, str]]]] = []
    for m in STRUCT_RE.finditer(stripped):
        open_at = m.start("open")
        if m.group("open") == "{":
            close = pairs.get(open_at)
            if close is None:
                continue
            body = stripped[open_at + 1 : close]
        else:
            depth = 0
            close = open_at
            for i in range(open_at, len(stripped)):
                if stripped[i] == "(":
                    depth += 1
                elif stripped[i] == ")":
                    depth -= 1
                    if depth == 0:
                        close = i
                        break
            body = stripped[open_at + 1 : close]
        fields: list[tuple[str, str]] = []
        for index, part in enumerate(_split_top(body)):
            part = re.sub(r"^(?:pub(?:\s*\([^)]*\))?\s+)", "", FIELD_ATTR_RE.sub("", part).strip())
            if m.group("open") == "{":
                if ":" not in part:
                    continue
                name, ty = part.split(":", 1)
                fields.append((name.strip(), ty.strip()))
            else:
                fields.append((str(index), part))
        derives = bool(DERIVES_DEFAULT_RE.search(m.group("attrs") or ""))
        out.append((m.start("name"), m.group("name"), derives, fields))
    return out


def reads(root: Path) -> list[tuple[str, int, str, str]]:
    """Every read of the build defaults in production code: (path, line, item, text).

    Besides a call that reads the build, two shapes read it without naming it: a struct with a
    field of a policy's type (or a `SessionPolicy`) that derives `Default`, whose `default()`,
    `..Default::default()` and every struct deriving from it take the build's value, read at the
    struct; and `<field>: Default::default()` where `<field>` is a field some struct gives a
    policy's type, read where it is written."""
    types = policy_types(root)
    pattern = read_re(types)
    held = set(types) | {"SessionPolicy"}
    all_sources = sources(root)
    test_only = cfg_test_files(all_sources)
    production: list[tuple[Path, str, list[tuple[int, int]]]] = []
    policy_fields: set[str] = set()
    found: list[tuple[str, int, str, str]] = []
    for path in all_sources:
        rel = path.relative_to(root)
        if rel == GENERATED or is_integration_test(rel) or path.resolve() in test_only:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        stripped = rust_comments.strip_comments(text, blank_literals=True)
        skip = cfg_test_spans(stripped)
        production.append((rel, stripped, skip))
        for at, name, derives, fields in struct_fields(stripped):
            if any(a <= at <= b for a, b in skip):
                continue
            typed = [(f, t) for f, t in fields if _last_segment(t) in held]
            policy_fields.update(f for f, _ in typed if not f.isdigit())
            if derives and typed:
                line = stripped.count("\n", 0, at) + 1
                said = ", ".join(f"{f}: {_last_segment(t)}" for f, t in typed)
                found.append((rel.as_posix(), line, name, f"derive(Default) of {said}"))
    for rel, stripped, skip in production:
        hits = list(pattern.finditer(stripped))
        inferred = [m for m in INFERRED_RE.finditer(stripped) if m.group("field") in policy_fields]
        if not hits and not inferred:
            continue
        spans = item_spans(stripped)
        for m in hits + inferred:
            if any(a <= m.start() <= b for a, b in skip):
                continue
            line = stripped.count("\n", 0, m.start()) + 1
            found.append((rel.as_posix(), line, enclosing_item(spans, m.start()), " ".join(m.group(0).split())))
    return sorted(found)


def allows(entry: tuple[str, str, str], path: str, item: str) -> bool:
    pattern, entry_item, _ = entry
    return fnmatch.fnmatchcase(path, pattern) and entry_item in ("*", item)


def is_exact(entry: tuple[str, str, str]) -> bool:
    """Whether `entry` names one site, and so is stale when no read is there."""
    return "*" not in entry[0] and entry[1] != "*"


def check(root: Path, allowed: tuple[tuple[str, str, str], ...]) -> tuple[list[str], int]:
    """The findings over `root` against `allowed`, and how many reads were found."""
    findings: list[str] = []
    seen: set[tuple[str, str]] = set()
    for entry in allowed:
        key = (entry[0], entry[1])
        if not entry[2].strip():
            findings.append(f"the allowed site {entry[0]} :: {entry[1]} states no reason")
        if key in seen:
            findings.append(f"the allowed site {entry[0]} :: {entry[1]} is listed twice")
        seen.add(key)
    found = reads(root)
    used: set[tuple[str, str]] = set()
    for path, line, item, text in found:
        entry = next((e for e in allowed if allows(e, path, item)), None)
        if entry is None:
            findings.append(
                f"{path}:{line} reads the build in `{item}` ({text}); a machine reads the "
                f"snapshot it is handed. Take a `SessionPolicy` from the creator, or list the "
                f"site in ALLOWED with the reason it is a creator"
            )
        else:
            used.add((entry[0], entry[1]))
    for entry in allowed:
        if is_exact(entry) and (entry[0], entry[1]) not in used:
            findings.append(
                f"the allowed site {entry[0]} :: {entry[1]} reads the build no longer; "
                f"take it off ALLOWED"
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
               "pub enum KeySet {\n    Open,\n}\n"
               "pub struct SessionPolicy {}\n"
               "impl SessionPolicy {\n    pub const fn defaults() -> Self { Self::from_build() }\n}\n"
               "fn f() { let _ = SessionPolicy::from_build(); KeySet::stated(); }\n")
        _write(root, "crates/a/src/lib.rs",
               "pub fn creator() -> SessionPolicy {\n    SessionPolicy::defaults()\n}\n"
               "pub fn machine() -> KeySet {\n    SessionPolicy::from_build().key_set()\n}\n"
               "pub fn by_type() -> KeySet {\n    KeySet::default()\n}\n"
               "pub fn by_trait() -> SessionPolicy {\n    <SessionPolicy as Default>::default()\n}\n"
               "pub fn outer() {\n    static CELL: u8 = 0;\n    let _ = SessionPolicy::default();\n}\n"
               "const FOLD: bool = {\n    let p = SessionPolicy::from_build();\n    true\n};\n"
               "pub fn arrayed() -> [u8; 2] {\n    let _ = SessionPolicy::defaults();\n    [0; 2]\n}\n"
               "pub fn generic<const N: usize>(s: &'static str) -> usize {\n"
               "    let _ = SessionPolicy::defaults();\n    N\n}\n"
               "// SessionPolicy::from_build() in a comment is prose.\n"
               "pub fn quoted() -> &'static str {\n    \"SessionPolicy::from_build()\"\n}\n"
               "pub fn snapshot(p: &SessionPolicy) -> KeySet {\n    p.key_set()\n}\n"
               "#[cfg(test)]\nmod tests {\n    fn t() { let _ = SessionPolicy::from_build(); }\n}\n"
               "#[cfg(all(\n    test,\n    feature = \"x\"\n))]\nmod more;\n"
               "#[derive(Debug, Default)]\npub struct Derived {\n    #[cfg(feature = \"x\")]\n"
               "    pub keys: crate::policy::KeySet,\n    pub hook: Box<dyn Fn(u8) -> u8>,\n}\n"
               "#[derive(Default)]\npub struct Wrapped(pub KeySet);\n"
               "#[derive(Default)]\npub struct Unrelated {\n    pub n: u8,\n    pub keys_seen: u32,\n}\n"
               "pub struct Plain {\n    pub keys: KeySet,\n}\n"
               "pub fn fill() -> Plain {\n    Plain { keys: Default::default() }\n}\n"
               "pub fn other() -> Unrelated {\n    Unrelated { n: Default::default(), keys_seen: 0 }\n}\n")
        _write(root, "crates/a/src/more.rs",
               "fn t() { let _ = SessionPolicy::default(); }\n"
               "#[derive(Default)]\nstruct InTest {\n    keys: KeySet,\n}\n")
        _write(root, "crates/a/tests/it.rs", "fn t() { let _ = SessionPolicy::from_build(); }\n")

        found = reads(root)
        got = {(path, item) for path, _, item, _ in found}
        want = {
            ("crates/a/src/lib.rs", "creator"),
            ("crates/a/src/lib.rs", "machine"),
            ("crates/a/src/lib.rs", "by_type"),
            ("crates/a/src/lib.rs", "by_trait"),
            ("crates/a/src/lib.rs", "outer"),
            ("crates/a/src/lib.rs", "FOLD"),
            ("crates/a/src/lib.rs", "arrayed"),
            ("crates/a/src/lib.rs", "generic"),
            # A derived `Default` over a policy's type reads the build at the struct, a tuple
            # field included; a struct with no such field, or none derived, does not.
            ("crates/a/src/lib.rs", "Derived"),
            ("crates/a/src/lib.rs", "Wrapped"),
            # A field of a policy's type filled from an inferred `Default` reads it there; a
            # field of another type filled the same way does not.
            ("crates/a/src/lib.rs", "fill"),
        }
        if got != want:
            failures.append(f"reads found {sorted(got)}, want {sorted(want)}")
        if len(found) != len(want):
            failures.append(f"{len(found)} reads found, want {len(want)}: one each")

        allowed = (
            ("crates/a/src/lib.rs", "creator", "a creator"),
            ("crates/a/src/lib.rs", "outer", "a creator"),
            ("crates/a/src/lib.rs", "FOLD", "a fold"),
            ("crates/a/src/lib.rs", "arrayed", "a creator"),
            ("crates/a/src/lib.rs", "by_trait", "a creator"),
            ("crates/a/src/lib.rs", "by_type", "a creator"),
            ("crates/a/src/lib.rs", "generic", "a creator"),
            ("crates/a/src/lib.rs", "Derived", "a creator"),
            ("crates/a/src/lib.rs", "Wrapped", "a creator"),
            ("crates/a/src/lib.rs", "fill", "a creator"),
        )
        findings, _ = check(root, allowed)
        refused = [f for f in findings if "reads the build in" in f]
        if len(refused) != 1 or "`machine`" not in refused[0]:
            failures.append(f"the one unlisted machine is refused, got {refused}")

        stale = allowed + (("crates/a/src/lib.rs", "gone", "a creator that left"),)
        findings, _ = check(root, stale)
        if not any("gone reads the build no longer" in f for f in findings):
            failures.append(f"a listed site with no read is stale, got {findings}")

        family = (("crates/a/src/*.rs", "*", "a family"), ("crates/b/src/*.rs", "*", "no file"))
        findings, _ = check(root, family)
        if findings:
            failures.append(f"a pattern allows its family and is never stale, got {findings}")

        bad = (("crates/a/src/lib.rs", "creator", " "), ("crates/a/src/lib.rs", "creator", "twice"))
        findings, _ = check(root, bad + allowed[1:])
        if not any("states no reason" in f for f in findings) or not any("listed twice" in f for f in findings):
            failures.append(f"an entry with no reason and a duplicate are refused, got {findings}")

    # The real list: each entry names a file that is there, and the family entry is the only
    # pattern.
    for pattern, item, reason in ALLOWED:
        if "*" in pattern:
            continue
        if not (REPO_ROOT / pattern).is_file():
            failures.append(f"ALLOWED names {pattern}, which is not a file")
        if not reason.strip() or not item:
            failures.append(f"ALLOWED entry {pattern} :: {item} is incomplete")

    if failures:
        for line in failures:
            print(f"  policy-read SELFTEST FAIL: {line}", file=sys.stderr)
        return 1
    print("  policy-read: selftest OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="hold the crates to ALLOWED")
    ap.add_argument("--selftest", action="store_true", help="drive every rule over a fixture tree")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.check:
        ap.error("state --check or --selftest")
    findings, count = check(REPO_ROOT, ALLOWED)
    if findings:
        print("policy-read FAIL:", file=sys.stderr)
        for line in findings:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print(f"  policy-read: {count} read(s) of the build defaults, each at one of {len(ALLOWED)} allowed site(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
