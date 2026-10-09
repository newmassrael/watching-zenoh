#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3172 (no register item) -- a reader tells an extension by its IDENTITY, not
by its 4-bit id. The class of item 860 of the unregistered register, which
lives outside this repository; that item was the first instance and is closed
by its own fix, so this gate closes no register item of its own.

## The defect this ends

Upstream tells a received extension apart by `iext::eid`, the header without
the chain flag: the id, the mandatory bit and the encoding together
(`commons/zenoh-protocol/src/common/extension.rs` @ `pub const fn eid(header: u8) -> u8 {`),
and every reader of a chain matches on it
(`commons/zenoh-codec/src/zenoh/put.rs` @ `Ok(match iext::eid(ext) {`). Two
extensions that share an id and differ in the other two are different
extensions, and the one a message does not declare is an unknown extension,
refused when it is mandatory. Item 860 found the `Put` codec matching its
shared-memory marker by the 4-bit id, the round after it found the `Query`
codec doing the same, and then twenty-four more functions in the crate sources that
read the id field and compared it against a bare constant: each of them took a
look-alike for the declared extension. Each was fixed by hand, and nothing
stopped the twenty-fifth.

## What is gated, and why the population is every READ of the id

A site is any non-test read of the 4-bit id field of an extension header in a
crate's `src`: the `.ext_id()` accessor, the `ext_id(..)` function, or a header
masked with the four-bit mask. Not only the comparisons: a read whose result is
compared two statements later is the same defect, and an expression parser that
followed the value would be a second compiler. So every read is a site, and
every site must be CLASSIFIED below, keyed by its file and the function it sits
in. An unclassified site is RED, and a classification whose function no longer
reads the id is RED too, so the table cannot outlive what it excuses.

The kinds a site may be, and none of them is "a reader that picks a received
extension out of a chain":

  * `upstream-id` -- upstream's own rule at that point IS the 4-bit id, cited;
  * `outbound` -- the chain this side stages for SENDING, where the id names the
    slot an entry it built replaces, and no received extension is told apart;
  * `renders` -- reports the id field as a field and compares nothing;
  * `family` -- composes headers from an identity for tests, reading no chain;
  * `hint` -- an observer's advisory flag that a look-alike can only widen, and
    that never makes the observer read a body as the extension.

The accessor's own definition (a function named `ext_id`) is not a site: it is
the thing every site calls.

## The codecs too

A generated codec names its chain's entries in its SCXML. `entry-id` naming the
4-bit id (`header.ext_id`) is the shape removed from `msg_put` (item 860) and
from `query`; a chain names the whole header without its continuation
flag, or nothing. That shape has no classification: there is no upstream codec
that tells an extension by its id.

## Measured, before wiring

Run on the tree as it stood after the reader fixes, the population is the
sites in the table and nothing else. Run on the tree as it stood BEFORE them
(exported and judged with the same `judge`), it reds on all twenty-four
functions, by file and function name, and on no other site. The
first draft read a doc comment that mentions the test attribute as the
attribute and so missed the integration harness's mask; `blank_comments` is
the repair, and the selftest holds it.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

#: A crate source file: `crates/<crate>/src/...rs`. Test crates (`tests/`) and
#: generated code (`out/`) are outside it on purpose -- a test asserts what a
#: writer emitted, and generated code is graded through its SCXML below.
RUST_SOURCE = re.compile(r"^crates/[^/]+/src/.+\.rs$")
SCXML_SOURCE = re.compile(r"^sources/.+\.scxml$")

#: A read of the 4-bit id field. The mask arm requires the masked operand to be
#: a header, so a nibble of some other byte (an IPv4 header length, a zid
#: length) is not read as one.
ID_READ = re.compile(
    r"""(?x)
    \.ext_id\(\)                                   # entry.ext_id()
  | (?<![\w.])(?:[\w:]+::)?ext_id\(                # ext_id(header), X::ext_id(e)
  | \w*header\w*(?:\(\))?\s*&\s*
      (?:0x0?[fF]\b|15\b|(?:EXT_)?ID_MASK\b)       # header & 0x0F
    """
)

#: An `entry-id` attribute that names the 4-bit id field of a chain's header.
SCXML_ID_ENTRY = re.compile(r"""entry-id\s*=\s*["'][^"']*\bext_id\b""")

FN_DECL = re.compile(r"\bfn\s+(\w+)\s*[<(]")

#: A test-only item: `#[cfg(test)]`, `#[cfg(all(test, ..))]` or `#[test]`.
TEST_ATTR = re.compile(r"#\[(?:cfg\((?:all\()?\s*test\b|test\])")

#: The classified sites, keyed by `(file, enclosing function)`.
CLASSIFIED: dict[tuple[str, str], tuple[str, str]] = {
    ("crates/wz-session-core/src/auth_dispatch.rs", "find_method_sub_ext"): (
        "upstream-id",
        "the method sub-extensions inside the auth extension are demultiplexed by "
        "their 4-bit id upstream: io/zenoh-transport/src/unicast/establishment/"
        "ext/auth/mod.rs @ .position(|x| x.id & iext::ID_MASK == $id)",
    ),
    ("crates/wz-session-core/src/dissect.rs", "walk_ext_entry_head"): (
        "renders",
        "the field layer reports the id column of a header as a field of its own",
    ),
    ("crates/wz-session-core/src/ext_header.rs", "lookalike_headers"): (
        "family",
        "builds every header that shares an id with an identity, the look-alike "
        "rows of the identity tests; it reads no chain",
    ),
    ("crates/wz-session-core/src/passive.rs", "has_any_ext_id"): (
        "hint",
        "the observer's offered flags for auth, shared memory and multilink are "
        "advisories that the session MAY use the capability; the offer comes in "
        "two encodings for shared memory, and the flags read no body",
    ),
    ("crates/wz-session-core/src/session_actions.rs", "stage_auth_send"): (
        "outbound",
        "replaces the auth entry this side stages in its own handshake chain",
    ),
    ("crates/wz-session-core/src/session_actions.rs", "stage_multilink_send"): (
        "outbound",
        "replaces the multilink entry this side stages in its own handshake chain",
    ),
    ("crates/wz-session-core/src/session_actions.rs", "staged_multilink_ext_count"): (
        "outbound",
        "counts the multilink entries this side staged for sending",
    ),
    ("crates/wz-session-core/src/session_actions.rs", "stage_negotiated_patch"): (
        "outbound",
        "replaces the patch entry this side stages in its own handshake chain",
    ),
    ("crates/wz-session-core/src/session_actions.rs", "stage_shm_challenge"): (
        "outbound",
        "replaces the shared-memory entry this side stages, in whichever of its "
        "two encodings it staged before",
    ),
    ("crates/wz-session-core/src/session_actions.rs", "stage_capability"): (
        "outbound",
        "replaces a capability entry this side stages in its own handshake chain",
    ),
}

KINDS = {"upstream-id", "outbound", "renders", "family", "hint"}

#: Below this the scan read the wrong tree: the workspace has hundreds of crate
#: source files, so a run that reads fewer found nothing to judge and must not
#: report OK.
MIN_RUST_FILES = 200
MIN_SCXML_FILES = 20


def strip_tests(text: str) -> str:
    """Blank every test-only item (attribute through its matched closing brace),
    keeping the line structure so line numbers still mean something. `text` has
    been through `blank_comments`, so every brace left is a brace of code."""
    pieces: list[str] = []
    copied = 0
    pos = 0
    while True:
        m = TEST_ATTR.search(text, pos)
        if not m:
            pieces.append(text[copied:])
            return "".join(pieces)
        brace = text.find("{", m.end())
        semi = text.find(";", m.end())
        if brace == -1 or (semi != -1 and semi < brace):
            # `#[cfg(test)] mod tests;` -- a file module; its file is judged on
            # its own (see `test_files`).
            pos = m.end()
            continue
        depth = 0
        end = len(text) - 1
        for b in BRACE.finditer(text, brace):
            depth += 1 if b.group() == "{" else -1
            if depth == 0:
                end = b.start()
                break
        pieces.append(text[copied : m.start()])
        pieces.append(BLANKABLE.sub(" ", text[m.start() : end + 1]))
        copied = pos = end + 1


def test_files(files: dict[str, str]) -> set[str]:
    """The files that are test modules declared `#[cfg(test)] mod <name>;` by
    their parent, which `strip_tests` cannot see from inside them."""
    found: set[str] = set()
    decl = re.compile(r"#\[cfg\((?:all\()?\s*test\b[^\]]*\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;")
    for rel, text in files.items():
        if "mod" not in text:
            continue
        parent = Path(rel)
        here = parent.parent if parent.name in ("lib.rs", "main.rs", "mod.rs") else parent.with_suffix("")
        for m in decl.finditer(text):
            for cand in (here / f"{m.group(1)}.rs", here / m.group(1) / "mod.rs"):
                found.add(cand.as_posix())
    return found


def blank_comments(text: str) -> str:
    """Blank comments, string literals and char literals, keeping every newline.

    FIRST, before anything looks for a test attribute or matches a brace. Two
    measured reasons: a doc comment that mentions `#[test]` is prose, and reading
    it as the attribute blanked every line up to the next closing brace, which
    hid a real 4-bit read in the integration harness; and a `}` inside a string
    or a char literal closed a test module early, which exposed a test helper in
    `linkstate_forward.rs` as product code.

    One alternation, scanned left to right, so whichever starts first wins: a
    `//` inside a string is part of the string, and a quote inside a comment is
    part of the comment. A char literal is a quote, one character or escape and
    a quote, which a lifetime (`'a`) never is."""
    return NON_CODE.sub(_blank_match, text)


def _blank_match(m: re.Match) -> str:
    s = m.group(0)
    return BLANKABLE.sub(" ", s) if "\n" in s else " " * len(s)


NON_CODE = re.compile(
    r"""//[^\n]*
      | /\*.*?\*/
      | (?<!\w)b?r(?P<hashes>\#*)".*?"(?P=hashes)
      | (?<!\w)b?"(?:\\.|[^"\\])*"
      | '(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^'\\\n])'
    """,
    re.S | re.X,
)
BLANKABLE = re.compile(r"[^\n]")
BRACE = re.compile(r"[{}]")


def sites(files: dict[str, str]) -> dict[tuple[str, str], list[int]]:
    """Every non-test read of the id field, keyed by `(file, function)`."""
    code_only = {rel: blank_comments(text) for rel, text in files.items()}
    skip = test_files(code_only)
    found: dict[tuple[str, str], list[int]] = {}
    for rel, text in sorted(code_only.items()):
        # Most files read no id at all; only those are walked line by line.
        if rel in skip or not ID_READ.search(text):
            continue
        current = "<module>"
        for n, code in enumerate(strip_tests(text).splitlines(), start=1):
            decl = FN_DECL.search(code)
            if decl:
                current = decl.group(1)
            if current == "ext_id" or not ID_READ.search(code):
                continue
            found.setdefault((rel, current), []).append(n)
    return found


def scxml_findings(files: dict[str, str]) -> list[str]:
    found = []
    for rel, text in sorted(files.items()):
        for n, line in enumerate(text.splitlines(), start=1):
            if SCXML_ID_ENTRY.search(line):
                found.append(f"{rel}:{n}: {line.strip()}")
    return found


def strip_xml_comments(text: str) -> str:
    """Blank `<!-- .. -->` spans, keeping lines: a comment that QUOTES the old
    attribute (both fixed codecs do, on purpose) is not the attribute."""
    return re.sub(r"<!--.*?-->", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)


def judge(
    rust: dict[str, str],
    scxml: dict[str, str],
    found: dict[tuple[str, str], list[int]] | None = None,
) -> list[str]:
    errors: list[str] = []
    if len(rust) < MIN_RUST_FILES or len(scxml) < MIN_SCXML_FILES:
        errors.append(
            f"read {len(rust)} crate source file(s) and {len(scxml)} SCXML file(s), "
            f"fewer than the {MIN_RUST_FILES} / {MIN_SCXML_FILES} this tree has: a "
            "gate that found nothing to judge must not report OK"
        )
        return errors
    if found is None:
        found = sites(rust)
    for key, lines in sorted(found.items()):
        if key not in CLASSIFIED:
            errors.append(
                f"{key[0]}:{lines[0]} (fn {key[1]}): reads an extension's 4-bit id; "
                "tell the extension by its identity (`ext_eid` against an identity "
                "constant, or `ext_view::find_by_eid`), or classify the site here "
                "with the upstream rule it follows"
            )
    for key, (kind, _reason) in sorted(CLASSIFIED.items()):
        if kind not in KINDS:
            errors.append(f"{key[0]} (fn {key[1]}): unknown kind {kind!r}")
        if key not in found:
            errors.append(
                f"{key[0]} (fn {key[1]}): classified as {kind!r} but reads no id any "
                "more; remove its row"
            )
    stripped = {rel: strip_xml_comments(text) for rel, text in scxml.items()}
    for finding in scxml_findings(stripped):
        errors.append(
            f"{finding}: a codec chain names its entries by the 4-bit id; name the "
            'whole header without its chain flag (entry-id="header" '
            'entry-id-except="header.Z"), or nothing'
        )
    return errors


def tracked(root: Path) -> tuple[dict[str, str], dict[str, str]]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", "crates", "sources"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout.decode()
    rust: dict[str, str] = {}
    scxml: dict[str, str] = {}
    for rel in filter(None, out.split("\0")):
        if RUST_SOURCE.match(rel):
            rust[rel] = (root / rel).read_text(encoding="utf-8", errors="replace")
        elif SCXML_SOURCE.match(rel):
            scxml[rel] = (root / rel).read_text(encoding="utf-8", errors="replace")
    return rust, scxml


def check() -> int:
    rust, scxml = tracked(REPO_ROOT)
    found = sites(rust)
    errors = judge(rust, scxml, found)
    if errors:
        print("ext-identity gate: FAIL", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    n_sites = sum(len(v) for v in found.values())
    print(
        f"ext-identity gate: OK ({len(rust)} crate source file(s), {len(scxml)} "
        f"SCXML file(s); {n_sites} read(s) of the 4-bit id in "
        f"{len(CLASSIFIED)} classified function(s), none in a codec chain)"
    )
    return 0


def selftest() -> int:
    """Drive `judge` over fixtures: each RED case must red, the GREEN one pass."""
    filler_rust = {f"crates/x/src/f{i}.rs": "fn f() {}\n" for i in range(MIN_RUST_FILES)}
    filler_scxml = {f"sources/c{i}.scxml": "<scxml/>\n" for i in range(MIN_SCXML_FILES)}
    def classified_files(rows) -> dict[str, str]:
        files: dict[str, str] = {}
        for rel, fn in rows:
            files[rel] = files.get(rel, "") + f"fn {fn}() {{ let _ = e.ext_id() == 3; }}\n"
        return files

    classified = classified_files(CLASSIFIED)

    def run(extra_rust: dict[str, str], extra_scxml: dict[str, str] | None = None, base=None):
        rust = dict(filler_rust)
        rust.update(classified if base is None else base)
        rust.update(extra_rust)
        scxml = dict(filler_scxml)
        scxml.update(extra_scxml or {})
        return judge(rust, scxml)

    red = {
        "method compare": {"crates/a/src/r.rs": "fn read(e: &E) -> bool { e.ext_id() == 0x03 }\n"},
        "free fn compare": {"crates/a/src/r.rs": "fn read(h: u8) -> bool { crate::ext_header::ext_id(h) != 5 }\n"},
        "trait path": {"crates/a/src/r.rs": "fn read(e: &E) -> bool { ExtEntryView::ext_id(e) == ID }\n"},
        "mask": {"crates/a/src/r.rs": "fn read(e: &E) -> bool { e.header & 0x0F != 0x03 }\n"},
        "named mask": {"crates/a/src/r.rs": "fn read(h: u8) -> u8 { ext_header & ID_MASK }\n"},
        "read then compare": {"crates/a/src/r.rs": "fn read(e: &E) -> bool {\n    let id = e.ext_id();\n    id == 3\n}\n"},
        # A doc comment that MENTIONS the test attribute is not one.
        "prose test attribute": {
            "crates/a/src/r.rs": "/// every `#[test]` in a file\nfn read(e: &E) -> bool { e.ext_id() == 3 }\n"
        },
    }
    failures = []
    for name, extra in red.items():
        if not run(extra):
            failures.append(f"RED case {name!r} passed")
    if not run({}, {"sources/q.scxml": '<sce:tlv-chain entry-id="header.ext_id"/>\n'}):
        failures.append("RED case 'scxml id entry' passed")
    # One classified function stops reading the id: its row is now stale.
    stale = classified_files(list(CLASSIFIED)[1:])
    first_file = next(iter(CLASSIFIED))[0]
    stale[first_file] = stale.get(first_file, "") + "fn other() {}\n"
    if not run({}, base=stale):
        failures.append("RED case 'stale classification' passed")
    if not judge({}, {}):
        failures.append("RED case 'empty population' passed")

    green = {
        "crates/a/src/ok.rs": (
            "pub fn ext_id(header: u8) -> u8 { header & 0x0F }\n"
            "fn read(e: &E) -> bool { ext_eid(e.header) == 0x43 }\n"
            "// a comment naming e.ext_id() == 3 is prose\n"
            "fn ihl(b: u8) -> usize { (b & 0x0F) as usize }\n"
            "#[cfg(test)]\nmod tests {\n    fn t(e: &E) { assert_eq!(e.ext_id(), 3); }\n}\n"
            "#[cfg(all(test, feature = \"x\"))]\nmod more { fn t(e: &E) { e.ext_id(); } }\n"
            "#[cfg(test)]\nmod split;\n"
        ),
        "crates/a/src/ok/split.rs": "fn t(e: &E) { assert_eq!(e.ext_id(), 3); }\n",
    }
    green_scxml = {
        "sources/p.scxml": (
            '<!-- the chain named the 4-bit id (`entry-id="header.ext_id"`) -->\n'
            '<sce:tlv-chain entry-id="header" entry-id-except="header.Z"/>\n'
        )
    }
    errors = run(green, green_scxml)
    if errors:
        failures.append(f"GREEN case reddened: {errors}")
    if failures:
        print("ext-identity gate selftest: FAIL", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"ext-identity gate selftest: OK ({len(red) + 3} red case(s) red, 1 green case green)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="extension identity gate")
    parser.add_argument("--check", action="store_true", help="judge this tree")
    parser.add_argument("--selftest", action="store_true", help="drive fixtures")
    args = parser.parse_args(argv)
    if args.check == args.selftest:
        parser.error("pass exactly one of --check / --selftest")
    if args.selftest:
        return selftest()
    return check()


if __name__ == "__main__":
    sys.exit(main())
