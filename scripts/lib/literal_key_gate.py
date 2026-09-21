#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2764 (no register item) -- the LITERAL COOKIE SIGNING KEY gate.

The debt it answers for lives in the UNREGISTERED set (item 105, the second
half of item 88), which is outside this repository, so there is no store id
for the provenance lint to resolve -- the position several gates here already
record for themselves.

## What it refuses, and why it exists

SessionInitParams::cookie_signing_key is the key behind the anti-amplification
cookie's HMAC. At R311y820 every params builder in this tree wrote it as a
literal -- a repeated byte pattern in the AP demo, the C ABI drive, the replay
live path and the MCU acceptor -- while the OS-entropy constructor, available
since R69, had ZERO production callers. Those literals are committed to a
PUBLIC repository, so the cookie key of every acceptor built from this tree
was public knowledge. The class leaked at FOUR sites before anyone counted
them, which is this project's own threshold for building a gate rather than
fixing instances.

## Why the bash predecessor was replaced rather than extended

R311y820 wrote the gate as a shell script that counted the needle per file and
compared each count against a hand-written `path:count` allowance. Its own
header said what every row of that allowance was: "a `#[cfg(test)] mod tests`
block or the test-support crate, i.e. a key that never reaches a shipped
acceptor." That sentence is the property the gate cares about, and NOTHING in
the script ever checked it. An asserted binding is not a binding, and this one
paid in both directions:

  * FALSE GREEN, the one a gate must never have. The allowance granted a
    COUNT, not a LOCATION. A file allowed five test keys could move one of
    them out of its test module and into a shipped constructor, and the count
    -- still five -- reported green while the exact defect this gate exists to
    stop had shipped.
  * FALSE RED, measured. R2762 added a test key to a new session file. The
    site was inside `#[cfg(test)] mod tests`, so the property the header
    claims to enforce held, and the gate reded anyway because the file had no
    row. Hosted Layer C0 died on it across three runs before anyone read the
    log, and the repair the gate asked for was an allowance edit -- a gate
    edit for a test, which is the cost its own header says the `tests/` prune
    exists to avoid.

Both faces are the same root: the gate measured a per-file COUNT where its
subject is a per-SITE PROPERTY. This module measures the property.

## The population is DERIVED, and an empty one FAILs

Tracked `*.rs` files with a `/src/` component under `crates/` or `deploy/`,
minus anything under a `tests/` directory -- an integration test is not a
shipped path. Tracked, via git, so build output under `crates/target` cannot
enter the walk the way a filesystem glob let it. Every needle site in those
files is a member; the gate prints the total and refuses a population of zero,
because a needle that matches nothing is a gate reporting on nothing.

## Classification, per site

  1. TEST-GATED, by structure. The site sits inside an item whose `cfg`
     predicate REQUIRES `test`, or inside a file that is reachable only
     through such an item. `all(test, feature = "x")` requires it; `any(...)`
     requires it only when every arm does; `not(...)` never does. A file
     declared `#[cfg(test)] mod name;` carries no marker inside itself, so
     that exclusion is resolved through the declaration and followed
     transitively -- the hole R2703 found in the sibling walk in
     subsystem_spawn_gate.py, which reads a narrower literal-only form.
     Allowed, with no row and no count: adding a test is not a gate edit.
  2. EXEMPT. The file is named below. This is the residue, and it keeps the
     predecessor's two-directional count, because where no structure decides
     the class a rise is a new literal to justify and a fall is a removal that
     has to say so in the same commit.
  3. Anything else FAILs.

## The exemption is bound to what IS derivable, and the rest is stated

A stronger derivation was attempted first and REFUTED, which is written down
here rather than discarded. The rule tried was "a package every one of whose
incoming workspace edges is a dev-dependency, transitively". Measured over the
58 workspace packages, it does NOT hold for the test-support crate below:
wz-e2e-harness takes it as an ORDINARY dependency, and eight wz-e2e-* binaries
take wz-e2e-harness the same way. That edge is real, not an artifact -- the
crate's own doc says the wz-e2e-* acceptor scaffolding derives its params from
these builders -- so the fixture key does reach built binaries. They are e2e
test peers rather than a shipped product, and no manifest fact separates those
two, which is why this row is a NAMED exception and not a derived class.

What the gate does check about an exemption is the one manifest fact that is
derivable and that the exception rests on: the row's package must declare
`publish = false`. That is NECESSARY, not sufficient, and saying so is the
point -- it reds if someone makes the crate publishable, and it does not
pretend to prove the crate never ships.

## Known blind spot, stated rather than implied

The needle reads a literal written AT the call. A key laid out as a named
constant and passed as `KEY.to_vec()` is the same defect and does not match.
Measured on the tree this round: every `SigningKey::new(` occurrence outside
the needle is either an entropy buffer being moved in, a length-rejection test
argument, or doc prose, so widening the needle to literal-argument forms
(`vec![`, an array, a byte string) left the site count unchanged at 12 while
closing three spellings the shell form could not see. The constant-indirection
form remains open.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# A construction whose argument is written as a literal AT the call. The three
# admitted openers are the spellings a `Vec<u8>` literal takes in Rust: the
# `vec!` macro, an array (usually with `.to_vec()`), and a byte string.
NEEDLE = re.compile(r"SigningKey\s*::\s*new\s*\(\s*(?:vec!\s*\[|\[|b?\")")

# Files whose literal keys no cfg predicate gates. Each row is a count, watched
# in both directions. The reason is prose on purpose: a row here is a judgement
# a person made, and the header says which part of it the gate can check.
EXEMPT: dict[str, int] = {
    # The test-support crate's two fixture builders. Deterministic by design:
    # the wire-interop fixtures pin the negotiation inputs, and a per-process
    # key would make them unreproducible. Not published; see the header for
    # the edge that stops this being a derived class.
    "crates/wz-runtime-tokio-test-support/src/lib.rs": 2,
}

# Cheap prefilters. Masking is a character walk, and running it over ~450
# sources costs seconds this hook does not need to pay. Both are SOUND in the
# safe direction: masking only blanks, so anything the masked text holds the
# raw text holds too -- a file with no `SigningKey` has no site, and one with
# no cfg attribute naming `test` has no test-gated item.
HAS_SITE = "SigningKey"
CFG_TEST_HINT = re.compile(r"#!?\[\s*cfg\s*\([^\]]*\btest\b")

RAW_OPEN = re.compile(r"b?r(#*)\"")
MOD_DECL = re.compile(r"\A\s*(?:pub\s*(?:\([^)]*\)\s*)?)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\Z")
PLAIN_MOD = re.compile(
    r"^[ \t]*(?:pub\s*(?:\([^)]*\)\s*)?)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", re.M
)


def mask(text: str) -> str:
    """`text` with comment and literal CONTENT blanked, length and lines kept.

    Every scan below -- for attributes, for braces, for the needle itself --
    runs over this rather than the source, so a needle quoted in a doc comment
    is not a construction and a brace inside a string is not a block. Offsets
    stay usable against the original because blanking preserves length.
    """
    out = list(text)
    n = len(text)
    i = 0

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c in "br" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            m = RAW_OPEN.match(text, i)
            if m is None:
                i += 1
                continue
            close = '"' + m.group(1)
            j = text.find(close, m.end())
            j = n if j < 0 else j + len(close)
            blank(i, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
        elif c == "'":
            # A lifetime is not a char literal, and treating one as the start
            # of a literal swallows the rest of the file.
            if i + 1 < n and text[i + 1] == "\\":
                j = text.find("'", i + 2)
                j = i + 2 if j < 0 else j + 1
                blank(i, j)
                i = j
            elif i + 2 < n and text[i + 2] == "'":
                blank(i, i + 3)
                i += 3
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def split_top(inner: str) -> list[str]:
    """Comma-separated parts of a cfg predicate, at paren depth zero."""
    parts, depth, start = [], 0, 0
    for idx, ch in enumerate(inner):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(inner[start:idx])
            start = idx + 1
    parts.append(inner[start:])
    return [p.strip() for p in parts if p.strip()]


def requires_test(pred: str) -> bool:
    """True when no build satisfying `pred` can omit `test`.

    `all` requires it when ANY arm does; `any` only when EVERY arm does --
    `any(test, feature = "x")` compiles with the feature and no test harness,
    which is a shipped path. `not` is refused outright: the safe direction for
    this gate to be wrong in is to call something production.
    """
    pred = pred.strip()
    if pred == "test":
        return True
    m = re.match(r"\A(all|any|not)\s*\((.*)\)\Z", pred, re.S)
    if m is None:
        return False
    op, parts = m.group(1), split_top(m.group(2))
    if not parts:
        return False
    if op == "all":
        return any(requires_test(p) for p in parts)
    if op == "any":
        return all(requires_test(p) for p in parts)
    return False


def attributes(masked: str):
    """(start, end, inner_slice, is_inner) for each attribute, `]` inclusive."""
    for m in re.finditer(r"#!?\[", masked):
        start = m.start()
        j = m.end() - 1
        depth = 0
        while j < len(masked):
            if masked[j] == "[":
                depth += 1
            elif masked[j] == "]":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        yield start, j, slice(m.end(), j), masked[start + 1] == "!"


def cfg_predicate(text: str, inner: slice) -> str | None:
    body = text[inner].strip()
    m = re.match(r"\Acfg\s*\((.*)\)\Z", body, re.S)
    return m.group(1) if m else None


def item_span(masked: str, attr_end: int) -> tuple[int, str]:
    """End offset of the item an attribute decorates, and its head text.

    A brace-less item -- `use`, a `mod name;` declaration, a type alias -- ends
    at its semicolon and has no interior. Brace-matching past it would swallow
    the NEXT item's block and call its contents test-gated, which is the false
    green this gate cannot afford.
    """
    i, n, depth = attr_end + 1, len(masked), 0
    while i < n:
        c = masked[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "{" and depth == 0:
            j, brace = i, 0
            while j < n:
                if masked[j] == "{":
                    brace += 1
                elif masked[j] == "}":
                    brace -= 1
                    if brace == 0:
                        break
                j += 1
            return min(j, n - 1), masked[attr_end + 1 : i]
        elif c == ";" and depth == 0:
            return i, masked[attr_end + 1 : i]
        i += 1
    return n - 1, masked[attr_end + 1 :]


def test_spans(text: str) -> list[tuple[int, int]]:
    """Offset spans this file gates behind `test`."""
    if CFG_TEST_HINT.search(text) is None:
        return []
    masked = mask(text)
    spans: list[tuple[int, int]] = []
    for start, end, inner, is_inner in attributes(masked):
        pred = cfg_predicate(text, inner)
        if pred is None or not requires_test(pred):
            continue
        if is_inner:
            # `#![cfg(test)]` gates everything the file holds.
            return [(0, len(text))]
        stop, _head = item_span(masked, end)
        spans.append((start, stop))
    return spans


def test_modules(text: str) -> list[str]:
    """Module names this file declares as test-only, in their own file."""
    if CFG_TEST_HINT.search(text) is None:
        return []
    masked = mask(text)
    names = []
    for _start, end, inner, is_inner in attributes(masked):
        if is_inner:
            continue
        pred = cfg_predicate(text, inner)
        if pred is None or not requires_test(pred):
            continue
        stop, head = item_span(masked, end)
        # Only the BRACE-LESS form names another file. An inline
        # `#[cfg(test)] mod tests { ... }` has the same head text, and reading
        # it as a declaration would mark a coincidental `tests.rs` sibling
        # test-only -- a false green over a file nothing gates.
        if masked[stop] != ";":
            continue
        m = MOD_DECL.match(head)
        if m:
            names.append(m.group(1))
    return names


def module_file(declarer: Path, name: str) -> Path | None:
    base = (
        declarer.parent
        if declarer.name in {"mod.rs", "lib.rs", "main.rs"}
        else declarer.with_suffix("")
    )
    for cand in (base / f"{name}.rs", base / name / "mod.rs"):
        if cand.is_file():
            return cand
    return None


def test_only_files(files: list[Path], texts: dict[Path, str] | None = None) -> set[Path]:
    """Files reachable only through a test-gated module declaration.

    TRANSITIVE: a module such a file declares is reachable from nowhere else,
    so it inherits the property. Stopping at depth one leaves the hole one
    level down.
    """
    cache = texts if texts is not None else {}
    frontier: list[Path] = []
    for path in files:
        text = cache.get(path)
        if text is None:
            text = path.read_text(encoding="utf-8", errors="replace")
        for name in test_modules(text):
            target = module_file(path, name)
            if target is not None:
                frontier.append(target)
    found: set[Path] = set()
    while frontier:
        path = frontier.pop()
        resolved = path.resolve()
        if resolved in found:
            continue
        found.add(resolved)
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for name in PLAIN_MOD.findall(mask(text)):
            target = module_file(path, name)
            if target is not None:
                frontier.append(target)
    return found


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


TABLE = re.compile(r"^\[([^\]]+)\]\s*$", re.M)
PUBLISH = re.compile(r"^\s*publish\s*=\s*(\S+)", re.M)


def package_table(text: str) -> str | None:
    """The body of `[package]`, or None when the manifest declares no package.

    Scoped rather than searched whole: `publish` also occurs under
    `[package.metadata.*]` and inside `[workspace.package]`, and a gate that
    read the first match anywhere would accept a key set for another table.
    Hand-scoped because the hosted floor interpreter is 3.10 and `tomllib`
    arrived in 3.11 -- the exact import that took Layer C0 down at R311y606.
    """
    bounds = [(m.group(1).strip(), m.start(), m.end()) for m in TABLE.finditer(text)]
    for idx, (name, _start, end) in enumerate(bounds):
        if name != "package":
            continue
        stop = bounds[idx + 1][1] if idx + 1 < len(bounds) else len(text)
        return text[end:stop]
    return None


def package_publishes(root: Path, rel: str) -> bool | None:
    """Whether the package owning `rel` may be published, or None if unknown.

    Anything other than a literal `false` is read as publishable, which is the
    safe direction: an unreadable manifest, a registry allow-list, or no key
    at all makes the exemption red rather than quietly granting it.
    """
    path = (root / rel).resolve()
    for parent in path.parents:
        manifest = parent / "Cargo.toml"
        if not manifest.is_file():
            continue
        try:
            body = package_table(manifest.read_text(encoding="utf-8"))
        except OSError:
            return None
        if body is None:
            continue
        m = PUBLISH.search(body)
        return not (m is not None and m.group(1).rstrip(",") == "false")
    return None


def source_files(root: Path, listing: list[str]) -> list[Path]:
    out = []
    for rel in listing:
        if not rel.endswith(".rs"):
            continue
        parts = rel.split("/")
        if parts[0] not in {"crates", "deploy"}:
            continue
        if "src" not in parts or "tests" in parts:
            continue
        path = root / rel
        if path.is_file():
            out.append(path)
    return sorted(out)


def tracked(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--", "crates", "deploy"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"literal-key: git ls-files failed (rc={result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return [line for line in result.stdout.split("\n") if line]


def evaluate(root: Path, files: list[Path], exempt: dict[str, int]):
    """(failures, counts) over `files`. Pure enough for the selftest to drive."""
    failures: list[str] = []
    texts = {p: p.read_text(encoding="utf-8", errors="replace") for p in files}
    only_test = test_only_files(files, texts)
    total = gated = 0
    ungated: dict[str, list[int]] = {}

    for path in files:
        text = texts[path]
        if HAS_SITE not in text:
            continue
        hits = [m.start() for m in NEEDLE.finditer(mask(text))]
        if not hits:
            continue
        total += len(hits)
        rel = path.relative_to(root).as_posix()
        if path.resolve() in only_test:
            gated += len(hits)
            continue
        spans = test_spans(text)
        for offset in hits:
            if any(a <= offset <= b for a, b in spans):
                gated += 1
            else:
                ungated.setdefault(rel, []).append(line_of(text, offset))

    for rel, lines in sorted(ungated.items()):
        where = ", ".join(str(n) for n in lines)
        if rel not in exempt:
            failures.append(
                f"{rel} builds a SigningKey from a literal outside any "
                f"test-gated item (line(s) {where}). A shipped acceptor's "
                f"cookie key must come from SigningKey::from_entropy -- a "
                f"literal here is published with the repo."
            )
            continue
        want = exempt[rel]
        if len(lines) > want:
            failures.append(
                f"{rel} has {len(lines)} ungated literal key site(s), "
                f"allowance {want} -- justify the new one or gate it"
            )
        elif len(lines) < want:
            failures.append(
                f"{rel} has {len(lines)} ungated literal key site(s) but the "
                f"allowance still says {want} -- lower it in this commit"
            )
        elif package_publishes(root, rel) is not False:
            failures.append(
                f"{rel} is exempt, and its package does not declare "
                f"publish = false -- the exemption rests on the crate not "
                f"being published, so that has to be true in the manifest"
            )

    for rel in sorted(exempt):
        if rel not in ungated:
            failures.append(
                f"the allowance names {rel}, which has no ungated literal key "
                f"site (or no longer exists) -- drop the row"
            )

    if total == 0:
        failures.append(
            "no site matched the needle anywhere in the population. A gate "
            "with nothing to grade is not a clean tree, it is a broken scan."
        )

    return failures, {
        "total": total,
        "gated": gated,
        "ungated": sum(len(v) for v in ungated.values()),
        "files": len(files),
    }


def run(root: Path) -> int:
    files = source_files(root, tracked(root))
    failures, counts = evaluate(root, files, EXEMPT)
    for line in failures:
        print(f"  literal-key FAIL: {line}")
    if failures:
        return 1
    print(
        f"  literal-key: {counts['total']} literal key site(s) over "
        f"{counts['files']} tracked source(s) -- {counts['gated']} gated "
        f"behind `test` by structure, {counts['ungated']} exempt by a named "
        f"row; no shipped path builds a cookie signing key from a literal"
    )
    return 0


PREDICATE_CASES = [
    ("test", True),
    ("all(test, feature = \"x\")", True),
    ("all(feature = \"x\", all(test, unix))", True),
    ("any(test, test)", True),
    ("any(test, feature = \"x\")", False),
    ("not(test)", False),
    ("feature = \"test\"", False),
    ("target_os = \"linux\"", False),
    ("all()", False),
]

GATED = "#[cfg(test)]\nmod tests {\n    fn k() { SigningKey::new(vec![7u8; 32]); }\n}\n"
COMPOUND = (
    "#[cfg(all(test, feature = \"x\"))]\nmod tests {\n"
    "    fn k() { SigningKey::new(vec![7u8; 32]); }\n}\n"
)
ANY_ARM = (
    "#[cfg(any(test, feature = \"x\"))]\nmod m {\n"
    "    fn k() { SigningKey::new(vec![7u8; 32]); }\n}\n"
)
SHIPPED = "fn k() { SigningKey::new(vec![7u8; 32]); }\n"
ARRAY = "fn k() { SigningKey::new([0u8; 32].to_vec()); }\n"
BRACELESS = (
    "#[cfg(test)]\nuse crate::signing_key::SigningKey;\n"
    "fn k() { SigningKey::new(vec![7u8; 32]); }\n"
)
QUOTED = "/// builds SigningKey::new(vec![7u8; 32]) for the caller\nfn k() {}\n"
LIFETIME = (
    "fn q<'a>(s: &'a str) -> &'a str { s }\n"
    "fn k() { SigningKey::new(vec![7u8; 32]); }\n"
)
INNER = "#![cfg(test)]\nfn k() { SigningKey::new(vec![7u8; 32]); }\n"

FILE_CASES = [
    ("a cfg(test) module is gated", GATED, 1, 0),
    ("all(test, feature) is gated", COMPOUND, 1, 0),
    ("any(test, feature) is NOT gated", ANY_ARM, 0, 1),
    ("a plain fn is not gated", SHIPPED, 0, 1),
    ("an array argument is a literal too", ARRAY, 0, 1),
    ("a brace-less cfg(test) item gates nothing after it", BRACELESS, 0, 1),
    ("a needle in a doc comment is not a site", QUOTED, 0, 0),
    ("a lifetime does not open a literal", LIFETIME, 0, 1),
    ("an inner cfg(test) gates the whole file", INNER, 1, 0),
]

MANIFEST = '[package]\nname = "p"\nversion = "0.0.0"\npublish = false\n'
PUBLISHED = '[package]\nname = "p"\nversion = "0.0.0"\n'
# `publish = false` set for a DIFFERENT table must not be read as the
# package's own -- the reason the table is scoped rather than searched.
ELSEWHERE = PUBLISHED + '\n[package.metadata.wz]\npublish = false\n'
LIB = "crates/p/src/lib.rs"

REFUSAL_ARMS = [
    ("an unlisted ungated site", MANIFEST, SHIPPED, {}, "outside any test-gated item"),
    ("a count that rose", MANIFEST, SHIPPED, {LIB: 0}, "justify the new one"),
    ("a count that fell", MANIFEST, SHIPPED, {LIB: 2}, "lower it"),
    ("a row with no site", MANIFEST, SHIPPED, {"crates/p/src/nope.rs": 1}, "drop the row"),
    ("an exempt row in a publishable package", PUBLISHED, SHIPPED, {LIB: 1}, "publish = false"),
    ("publish = false under another table", ELSEWHERE, SHIPPED, {LIB: 1}, "publish = false"),
    ("an empty population", MANIFEST, "fn k() {}\n", {}, "broken scan"),
]


def _tree(root: Path, manifest: str, body: str) -> list[Path]:
    src = root / "crates" / "p" / "src"
    src.mkdir(parents=True, exist_ok=True)
    (root / "crates" / "p" / "Cargo.toml").write_text(manifest, encoding="utf-8")
    (src / "lib.rs").write_text(body, encoding="utf-8")
    return [src / "lib.rs"]


def selftest() -> int:
    failures: list[str] = []

    for pred, want in PREDICATE_CASES:
        got = requires_test(pred)
        if got != want:
            failures.append(f"requires_test({pred!r}) = {got}, want {want}")

    for name, body, want_gated, want_ungated in FILE_CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = _tree(root, MANIFEST, body)
            _f, counts = evaluate(root, files, {"crates/p/src/lib.rs": want_ungated})
            if counts["gated"] != want_gated or counts["ungated"] != want_ungated:
                failures.append(
                    f"{name}: gated={counts['gated']} ungated={counts['ungated']}, "
                    f"want gated={want_gated} ungated={want_ungated}"
                )

    # A file reached only through `#[cfg(test)] mod name;` carries no marker of
    # its own, and the exclusion is inherited by what IT declares.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "crates" / "p" / "src"
        # `mod deep;` inside `t.rs` resolves under `t/`, not beside it.
        (src / "t" / "deep").mkdir(parents=True)
        (root / "crates" / "p" / "Cargo.toml").write_text(MANIFEST, encoding="utf-8")
        (src / "lib.rs").write_text("#[cfg(test)]\nmod t;\nmod live;\n", encoding="utf-8")
        (src / "t.rs").write_text(
            "mod deep;\nfn k() { SigningKey::new(vec![1u8; 32]); }\n", encoding="utf-8"
        )
        (src / "t" / "deep" / "mod.rs").write_text(SHIPPED, encoding="utf-8")
        (src / "live.rs").write_text(SHIPPED, encoding="utf-8")
        files = [src / "lib.rs", src / "t.rs", src / "t" / "deep" / "mod.rs", src / "live.rs"]
        _f, counts = evaluate(root, files, {"crates/p/src/live.rs": 1})
        if counts["gated"] != 2 or counts["ungated"] != 1:
            failures.append(
                "a test-only module file and what it declares must both be "
                f"gated, and a plain sibling must not: gated={counts['gated']} "
                f"ungated={counts['ungated']}, want 2 / 1"
            )

    # An INLINE `#[cfg(test)] mod tests { ... }` has the same head text as a
    # declaration of `tests.rs`, and reading it as one would gate a file
    # nothing declares. The sibling here is the anti-vacuity arm: it must stay
    # ungated, or this case passes for a gate that marks everything test-only.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "crates" / "p" / "src"
        src.mkdir(parents=True)
        (root / "crates" / "p" / "Cargo.toml").write_text(MANIFEST, encoding="utf-8")
        (src / "lib.rs").write_text("#[cfg(test)]\nmod tests {}\n", encoding="utf-8")
        (src / "tests.rs").write_text(SHIPPED, encoding="utf-8")
        files = [src / "lib.rs", src / "tests.rs"]
        _f, counts = evaluate(root, files, {"crates/p/src/tests.rs": 1})
        if counts["gated"] != 0 or counts["ungated"] != 1:
            failures.append(
                "an inline `mod tests {}` must not gate a coincidental "
                f"tests.rs: gated={counts['gated']} ungated={counts['ungated']}"
                ", want 0 / 1"
            )

    # Every refusal branch, driven red-first. A branch nothing reaches is a
    # verdict nobody can get, so each arm names the sentence it expects back.
    for label, manifest, body, exempt, needle in REFUSAL_ARMS:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = _tree(root, manifest, body)
            found, _c = evaluate(root, files, exempt)
            if not any(needle in line for line in found):
                failures.append(f"{label}: no failure saying {needle!r}; got {found}")

    if failures:
        print("literal-key SELFTEST FAIL:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print(
        f"  literal-key selftest: {len(PREDICATE_CASES)} predicate case(s) + "
        f"{len(FILE_CASES)} file case(s) + 2 module-resolution case(s) + "
        f"{len(REFUSAL_ARMS)} refusal arm(s) OK"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(REPO_ROOT))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run(Path(args.root).resolve())


if __name__ == "__main__":
    sys.exit(main())
