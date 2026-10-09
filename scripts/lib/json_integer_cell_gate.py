#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3013 (no register item) — EVERY JSON CELL THAT TAKES THE INTEGER DOOR IS NAMED
WHERE A CONSUMER READS ABOUT IT.

The citation reads `no register item` for the reason `round_fed_gate_reach.py`
gives for its own: the class is recorded in the operator's agent-memory register,
which has no store `debt-` id for `gate_provenance_lint.py` to resolve.

## The defect, found by a consumer

R3012 made a 64-bit integer that a JSON number would misread a string past
2^53 - 1 (`wz_session_core::json::u64_into`, and its allocating form
`u64_json` in `wz-capture`'s report). A cell that takes that door can be a number
OR a string, and the only notice a consumer gets of that is prose: the revision
row each document's `DocumentShape` carries in `doc_revision.rs`, and the
integer paragraph of the public header `wz_dissect.h`.

The cell list was written by reading the writers. The header came out complete;
the rows did not. The fields row said the revision moved "one value" (a `uint`
field's) and that the rule held nowhere but the retention document, while the
same commit had sent a row's `sn.missing` through the door; the census row said
"one value" over five cells, the summary row "three" over five. A consumer
caught the first by reading `fields_json.rs`, which is the reading this gate now
does on every push.

## What it checks

1. THE SITES ARE DERIVED. Every call of a door in the non-test code of every
   crate under `crates/` is found by its enclosing function, with comments,
   strings and `#[cfg(test)]` modules masked out. `CELLS` must declare, for each
   `(file, fn)`, exactly as many cells as that function has calls -- a new call
   in a declared function, a call in an undeclared one, and a declared function
   that lost its call are all findings. The door definitions themselves are not
   cells.
2. THE HEADER NAMES EVERY CELL. Each cell's `header` phrase must stand in the
   integer paragraph of `wz_dissect.h`, and the paragraph's `Revisions:` sentence
   must name exactly the revision `RULE_REVISION` gives each document.
3. THE ROW NAMES EVERY CELL. Each cell's `row` phrase must stand in the comment
   block directly above that document's `DocumentShape` at its rule revision.

Phrases are compared with whitespace and comment markers collapsed, so a
re-wrapped sentence is the same sentence.

## What it does NOT see

A JSON writer that formats a `u64` bare without the door (`write!(out, "{v}")`).
Telling that from a count the host bounds needs the value's provenance, which a
text scan cannot have; the header's own rule says which is which. A door call
reached through a helper this table does not know as a door is the same blind
spot, and the two doors are named in `DOORS` so a third is one line. A file named
`tests.rs` is test code (it is a `#[cfg(test)] mod tests;` body), and is skipped.
"""

from __future__ import annotations

import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Iterable, Mapping

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The integer door and its allocating form.
DOORS = ("u64_into", "u64_json")
#: Where each door is DEFINED: a call inside these bodies is the door, not a cell.
DOOR_DEFINITIONS = frozenset(
    {
        ("crates/wz-session-core/src/json.rs", "u64_into"),
        ("crates/wz-capture/src/report.rs", "u64_json"),
    }
)
HEADER = "crates/wz-capi-dissect/include/wz_dissect.h"
#: The integer paragraph runs from this marker to the next `@values` line.
HEADER_START = "AN INTEGER A JSON NUMBER WOULD MISREAD IS A STRING"
HEADER_END = "@values"
DOC_REVISION = "crates/wz-capture/src/doc_revision.rs"

#: The revision at which each document took the rule, in the order the header's
#: `Revisions:` sentence names them.
RULE_REVISION: dict[str, int] = {
    "fields": 23,
    "census": 16,
    "summary": 5,
    "retention": 2,
    "e2e_wrap": 1,
    "e2e_open": 1,
}


@dataclass(frozen=True)
class Cell:
    document: str
    name: str
    header: str
    row: str
    #: The revision at which THIS cell first existed under the rule, when that is
    #: later than its document's `RULE_REVISION`. A cell added after the document
    #: took the rule is born under it, so the row that announced the cell is the
    #: row of the revision that added it and not the one that introduced the rule.
    #: `None` is the document's own rule revision.
    born: int | None = None


_ID_HEADER = "the `id` and `solicited_by` values the census and the summary write"
_HALVES_HEADER = "the `lease_ms` and `last_seen_ts_ns` of a flow's `halves`"
_LATENCY_HEADER = "the `min_ns`, `max_ns`, `mean_ns` and `total_ns` of a census latency object"
#: The protected-frame documents take the rule from their first revision. The
#: field cells are written by ONE helper both documents share, so they are
#: declared once, under `e2e_wrap`, and the `e2e_open` row names them as well.
_E2E_FIELD_HEADER = "the `raw` and `value` of an `e2e_wrap` or `e2e_open` field and the `value` of each of its `parts`"
_E2E_DOCUMENT_HEADER = "the `crc_computed` and `length_field` of an `e2e_wrap` or `e2e_open` document"
#: The `e2e` block of a field-document entry (revision 34) writes its own
#: numbers through the door; the block's `header` fields come out of the same
#: helper the two stateless documents use, so those cells are declared above.
_E2E_BLOCK_HEADER = (
    "the `crc_computed`, `length_field`, `length_expected`, `counter` and `silence_ms` "
    "of an `e2e` block and the `value` of each entry of its `slot.identity`"
)

#: (file, enclosing fn) -> the cells that function writes through a door, one per call.
CELLS: dict[tuple[str, str], tuple[Cell, ...]] = {
    ("crates/wz-session-core/src/dissect.rs", "push_json"): (
        Cell("fields", "a `bits` field's value", "a `uint` (and a `bits`) field's `value`", "`bits`"),
        Cell("fields", "a `uint` field's value", "a `uint` (and a `bits`) field's `value`", "`uint`"),
    ),
    ("crates/wz-capture/src/fields_json.rs", "push_session_row"): (
        Cell("fields", "a row's sn.missing", "the `missing` of a row's `sn`", "`sn.missing`"),
    ),
    ("crates/wz-capture/src/fields_json.rs", "push_keyexpr_miss"): (
        Cell(
            "fields",
            "a carried entry's keyexpr_id",
            "the `keyexpr_id` of a `carried` entry",
            "`keyexpr_id` is a protocol field's value",
            born=24,
        ),
    ),
    ("crates/wz-capture/src/fields_json.rs", "push_halves"): (
        Cell("fields", "a half's lease_ms", _HALVES_HEADER, "`lease_ms` is a wire field's value", born=25),
        Cell("fields", "a half's last_seen_ts_ns", _HALVES_HEADER, "`last_seen_ts_ns` a nanosecond instant", born=25),
    ),
    ("crates/wz-capture/src/census_json.rs", "interests_json"): (
        Cell("census", "declarations[].id", _ID_HEADER, "`declarations[].id`"),
        Cell("census", "a declaration's unresolved.id", _ID_HEADER, "`unresolved.id`"),
        Cell("census", "declarations[].solicited_by", _ID_HEADER, "`declarations[].solicited_by`"),
        Cell("census", "requests[].id", _ID_HEADER, "`requests[].id`"),
    ),
    ("crates/wz-capture/src/census_json.rs", "keyexprs_json"): (
        Cell("census", "an unresolved alias's id", _ID_HEADER, "an unresolved alias's `id`"),
    ),
    # One cell per CALL, and `push_latency` loops three of its four nanosecond
    # figures through one call, so the loop is declared once and `total_ns`
    # (a SUM, the one a long capture can carry past the line) once.
    ("crates/wz-capture/src/census_json.rs", "push_latency"): (
        Cell(
            "census",
            "a latency's min_ns, max_ns and mean_ns",
            _LATENCY_HEADER,
            "`min_ns`, `max_ns`, `mean_ns` and `total_ns`",
            born=17,
        ),
        Cell("census", "a latency's total_ns", _LATENCY_HEADER, "`total_ns` is a SUM", born=17),
    ),
    ("crates/wz-capture/src/report.rs", "capture_json"): (
        Cell("summary", "an interest's id", _ID_HEADER, "the `id` and `solicited_by` of an interest"),
        Cell("summary", "an interest's solicited_by", _ID_HEADER, "`solicited_by` of an interest"),
        Cell("summary", "a request's id", _ID_HEADER, "the `id` of a request"),
    ),
    ("crates/wz-capture/src/report.rs", "throughput_json"): (
        Cell("summary", "an unresolved alias's id", _ID_HEADER, "of an unresolved alias"),
    ),
    ("crates/wz-capture/src/report.rs", "sequence_json"): (
        Cell("summary", "the sequence group's missing", "of the summary's `sequence` group", "the sequence group's `missing`"),
    ),
    ("crates/wz-capture/src/retention_json.rs", "retention_json"): (
        Cell("retention", "oldest_ts_ns", "`oldest_ts_ns` in the retention document", "`oldest_ts_ns`"),
    ),
    ("crates/wz-capture/src/e2e_row.rs", "push_opened"): (
        Cell("fields", "an e2e block's crc_computed", _E2E_BLOCK_HEADER, "`crc_computed`", born=34),
        Cell("fields", "an e2e block's length_field", _E2E_BLOCK_HEADER, "`length_field`", born=34),
        Cell("fields", "an e2e block's length_expected", _E2E_BLOCK_HEADER, "`length_expected`", born=34),
        Cell("fields", "an e2e block's counter", _E2E_BLOCK_HEADER, "a frame's `counter`", born=34),
        Cell(
            "fields",
            "an identity entry's value",
            _E2E_BLOCK_HEADER,
            "the `value` of each `identity` entry",
            born=34,
        ),
    ),
    ("crates/wz-capture/src/e2e_row.rs", "push_optional"): (
        Cell("fields", "an e2e block's silence_ms", _E2E_BLOCK_HEADER, "`silence_ms`", born=34),
    ),
    ("crates/wz-capture/src/e2e_json.rs", "push_fields"): (
        Cell("e2e_wrap", "a field's raw", _E2E_FIELD_HEADER, "a field's `raw`"),
        Cell("e2e_wrap", "a field's value", _E2E_FIELD_HEADER, "a field's `value`"),
        Cell("e2e_wrap", "a part's value", _E2E_FIELD_HEADER, "a part's `value`"),
    ),
    ("crates/wz-capture/src/e2e_json.rs", "wrap_document"): (
        Cell("e2e_wrap", "crc_computed", _E2E_DOCUMENT_HEADER, "`crc_computed`"),
        Cell("e2e_wrap", "length_field", _E2E_DOCUMENT_HEADER, "`length_field`"),
    ),
    ("crates/wz-capture/src/e2e_json.rs", "open_document"): (
        Cell("e2e_open", "crc_computed", _E2E_DOCUMENT_HEADER, "`crc_computed`"),
        Cell("e2e_open", "length_field", _E2E_DOCUMENT_HEADER, "`length_field`"),
        Cell(
            "e2e_open",
            "length_expected",
            "the `length_expected` of an `e2e_open` document",
            "`length_expected`",
        ),
    ),
}


# ─── masking: comments and literals blanked, offsets kept ────────────────────


def mask(text: str) -> str:
    """`text` with comments and string/char literal contents replaced by spaces.

    Newlines survive, so offsets and line numbers stay valid. A lifetime (`'a`) is
    not a char literal: a quote is a literal only when a closing quote follows one
    character or one escape later.
    """
    out = list(text)
    i, n = 0, len(text)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c == "r" and re.match(r'r#*"', text[i:]) and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            hashes = len(re.match(r"r(#*)\"", text[i:]).group(1))
            end = text.find('"' + "#" * hashes, i + 2 + hashes)
            end = n if end < 0 else end + 1 + hashes
            blank(i + 1, end)
            i = end
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank(i + 1, j)
            i = j + 1
        elif c == "'":
            m = re.match(r"'(\\.[^']*|[^\\'\n])'", text[i:])
            if m:
                blank(i + 1, i + m.end() - 1)
                i += m.end()
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def _matching_brace(masked: str, open_at: int) -> int:
    depth = 0
    for k in range(open_at, len(masked)):
        if masked[k] == "{":
            depth += 1
        elif masked[k] == "}":
            depth -= 1
            if depth == 0:
                return k
    return len(masked)


_TEST_MOD = re.compile(
    r"#\[cfg\([^\]]*\btest\b[^\]]*\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{"
)
_FN = re.compile(r"\bfn\s+([A-Za-z_]\w*)")
_CALL = re.compile(r"\b(" + "|".join(DOORS) + r")\s*\(")


def door_sites(text: str) -> list[tuple[str, int]]:
    """(enclosing fn, line) of every door call in the non-test code of one file."""
    masked = mask(text)
    # Blank every inline `#[cfg(test)]` module.
    chars = list(masked)
    for m in _TEST_MOD.finditer(masked):
        end = _matching_brace(masked, m.end() - 1)
        for k in range(m.start(), end + 1):
            if chars[k] != "\n":
                chars[k] = " "
    masked = "".join(chars)
    spans: list[tuple[int, int, str]] = []
    for m in _FN.finditer(masked):
        brace = masked.find("{", m.end())
        semi = masked.find(";", m.end())
        if brace < 0 or (0 <= semi < brace):
            continue  # a declaration without a body
        spans.append((m.start(), _matching_brace(masked, brace), m.group(1)))
    sites: list[tuple[str, int]] = []
    for c in _CALL.finditer(masked):
        if re.search(r"\bfn\s+$", masked[max(0, c.start() - 16) : c.start()]):
            continue  # the definition's own signature
        inside = [s for s in spans if s[0] < c.start() <= s[1]]
        name = min(inside, key=lambda s: s[1] - s[0])[2] if inside else "?"
        sites.append((name, masked.count("\n", 0, c.start()) + 1))
    return sites


def derive_sites(files: Mapping[str, str]) -> dict[tuple[str, str], list[int]]:
    found: dict[tuple[str, str], list[int]] = {}
    for rel, text in sorted(files.items()):
        if pathlib.PurePosixPath(rel).name == "tests.rs":
            continue  # a `#[cfg(test)] mod tests;` body is test code
        for fn, line in door_sites(text):
            if (rel, fn) in DOOR_DEFINITIONS:
                continue
            found.setdefault((rel, fn), []).append(line)
    return found


# ─── the three checks ────────────────────────────────────────────────────────


def _flat(s: str) -> str:
    s = re.sub(r"^\s*(?:///|//!|//|\*)\s?", "", s, flags=re.M)
    return re.sub(r"\s+", " ", s).strip()


def site_findings(
    found: Mapping[tuple[str, str], list[int]], cells: Mapping[tuple[str, str], tuple[Cell, ...]]
) -> list[str]:
    out: list[str] = []
    for key in sorted(set(found) | set(cells)):
        rel, fn = key
        have = found.get(key, [])
        want = cells.get(key, ())
        if not want:
            out.append(
                f"{rel}: `{fn}` writes {len(have)} cell(s) through the integer door "
                f"(line(s) {', '.join(map(str, have))}) that CELLS does not declare. Name each "
                f"cell, and say it in the header's integer paragraph and in its document's row."
            )
        elif not have:
            out.append(f"{rel}: CELLS declares `{fn}`, which calls no integer door any more")
        elif len(have) != len(want):
            out.append(
                f"{rel}: `{fn}` calls the integer door {len(have)} time(s) (line(s) "
                f"{', '.join(map(str, have))}) and CELLS declares {len(want)} cell(s) for it"
            )
    return out


def header_paragraph(header: str) -> str | None:
    start = header.find(HEADER_START)
    if start < 0:
        return None
    end = header.find(HEADER_END, start)
    return _flat(header[start : end if end >= 0 else len(header)])


def header_findings(header: str, cells: Iterable[Cell], rule: Mapping[str, int]) -> list[str]:
    para = header_paragraph(header)
    if para is None:
        return [f"{HEADER}: the integer paragraph (`{HEADER_START}`) is not there"]
    out = [
        f"{HEADER}: the integer paragraph does not name {c.document}'s {c.name} "
        f"(it should say: {_flat(c.header)})"
        for c in cells
        if _flat(c.header) not in para
    ]
    want = "Revisions: " + ", ".join(f"{d} {r}" for d, r in rule.items()) + "."
    if want not in para:
        out.append(f"{HEADER}: the integer paragraph's revision sentence is not `{want}`")
    return out


def _const_for(doc_revision: str) -> dict[str, str]:
    # Digits are part of a name (`e2e_wrap`): a class that stopped at letters and
    # underscores would have no constant for such a document and report its row
    # as missing.
    return {
        m.group(2): m.group(1)
        for m in re.finditer(r'pub const ([A-Z0-9_]+): &str = "([a-z0-9_]+)";', doc_revision)
    }


def row_comment(doc_revision: str, document: str, revision: int) -> str | None:
    const = _const_for(doc_revision).get(document)
    if const is None:
        return None
    m = re.search(
        r"((?:^[ \t]*//[^\n]*\n)+)[ \t]*DocumentShape \{\s*document: " + const + r",\s*revision: " + str(revision) + r",",
        doc_revision,
        flags=re.M,
    )
    return _flat(m.group(1)) if m else None


def row_findings(doc_revision: str, cells: Iterable[Cell], rule: Mapping[str, int]) -> list[str]:
    """Each cell is looked for in the row of the revision it was born under: its own
    `born`, or its document's rule revision when it has none. A document with cells
    born at two revisions is read at both, and each row must name its own."""
    out: list[str] = []
    cells = list(cells)
    for doc, rule_rev in rule.items():
        mine = [c for c in cells if c.document == doc]
        for rev in sorted({rule_rev} | {c.born for c in mine if c.born is not None}):
            text = row_comment(doc_revision, doc, rev)
            here = [c for c in mine if (c.born if c.born is not None else rule_rev) == rev]
            if text is None:
                out.append(f"{DOC_REVISION}: no commented `DocumentShape` row for {doc} revision {rev}")
                continue
            out += [
                f"{DOC_REVISION}: the {doc} revision {rev} row does not name {c.name} "
                f"(it should say: {_flat(c.row)})"
                for c in here
                if _flat(c.row) not in text
            ]
    return out


def tracked_writers() -> dict[str, str]:
    files: dict[str, str] = {}
    for p in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
        files[str(p.relative_to(ROOT))] = p.read_text(encoding="utf-8")
    return files


def check() -> int:
    files = tracked_writers()
    found = derive_sites(files)
    if not found:
        print("json-integer-cell: FAIL -- no integer-door call found anywhere; the reader stopped reading")
        return 1
    cells = [c for group in CELLS.values() for c in group]
    findings = site_findings(found, CELLS)
    findings += header_findings((ROOT / HEADER).read_text(encoding="utf-8"), cells, RULE_REVISION)
    findings += row_findings((ROOT / DOC_REVISION).read_text(encoding="utf-8"), cells, RULE_REVISION)
    if findings:
        print(f"json-integer-cell: FAIL -- {len(findings)} finding(s)")
        for f in findings:
            print(f"  {f}")
        return 1
    print(
        f"  json-integer-cell: {sum(len(v) for v in found.values())} door call(s) in "
        f"{len(found)} writer function(s) over {len(files)} file(s), each named in the header "
        f"and in its document's row ({', '.join(f'{d} {r}' for d, r in RULE_REVISION.items())})"
    )
    return 0


# ─── selftest ────────────────────────────────────────────────────────────────


def selftest() -> int:
    failures: list[str] = []

    def expect(label: str, got: object, want: object) -> None:
        if got != want:
            failures.append(f"{label}: got {got!r}, want {want!r}")

    def refused(label: str, got: list[str], needle: str) -> None:
        if not any(needle in g for g in got):
            failures.append(f"{label}: expected a finding containing {needle!r}, got {got!r}")

    src = (
        "fn a(out: &mut String) {\n"
        "    // u64_into(1, out) in a comment is not a call\n"
        "    let s = \"u64_into(2, out)\";\n"
        "    let _l: &'static str = s;\n"
        "    u64_into(3, out);\n"
        "    let c = |x| { json::u64_into(x, out) };\n"
        "}\n"
        "fn encode(v: u64) { encode_vle_u64_into(v); }\n"
        "fn u64_json(v: u64) -> String { let mut s = String::new(); u64_into(v, &mut s); s }\n"
        "#[cfg(test)]\nmod tests {\n    fn t() { u64_into(9, &mut String::new()); }\n}\n"
        "fn b() { let _ = r#\"u64_json(1)\"#; u64_json(4); }\n"
    )
    sites = door_sites(src)
    expect("calls by fn, comments/strings/tests masked", sorted(sites), [("a", 5), ("a", 6), ("b", 14), ("u64_json", 9)])
    found = derive_sites({"crates/wz-capture/src/report.rs": src})
    expect("the door definition is not a cell", sorted(found), [("crates/wz-capture/src/report.rs", "a"), ("crates/wz-capture/src/report.rs", "b")])
    expect(
        "a separate tests.rs is test code",
        derive_sites({"crates/wz-capture/src/x/tests.rs": "fn t() { u64_json(1); }\n"}),
        {},
    )

    c1 = Cell("fields", "x", "the `x` cell", "`x`")
    c2 = Cell("fields", "y", "the `y` cell", "`y`")
    key = ("f.rs", "a")
    expect("a matching table is clean", site_findings({key: [5, 6]}, {key: (c1, c2)}), [])
    refused("a new call in a declared fn", site_findings({key: [5, 6, 7]}, {key: (c1, c2)}), "3 time(s)")
    refused("an undeclared fn", site_findings({("f.rs", "z"): [1]}, {}), "does not declare")
    refused("a declared fn lost its call", site_findings({}, {key: (c1,)}), "calls no integer door")

    header = (
        " * ⚠ AN INTEGER A JSON NUMBER WOULD MISREAD IS A STRING (fields 2).\n"
        " * It applies to the `x` cell and to the\n * `y` cell. Revisions: fields 2.\n *\n * @values x\n"
    )
    rule = {"fields": 2}
    expect("a header naming both cells, re-wrapped", header_findings(header, [c1, c2], rule), [])
    refused("a header missing a cell", header_findings(header.replace("`y`", "`q`"), [c1, c2], rule), "does not name fields's y")
    refused("a wrong revision sentence", header_findings(header, [c1], {"fields": 3}), "revision sentence")
    refused("no paragraph at all", header_findings("nothing", [c1], rule), "is not there")

    rows = (
        'pub const FIELDS: &str = "fields";\n'
        "    // the row names `x` and\n    // `y` too.\n"
        "    DocumentShape {\n        document: FIELDS,\n        revision: 2,\n"
    )
    expect("a row naming both cells", row_findings(rows, [c1, c2], rule), [])
    refused("a row missing a cell", row_findings(rows.replace("`y`", "`q`"), [c1, c2], rule), "does not name y")
    refused("no row at the rule revision", row_findings(rows, [c1], {"fields": 3}), "no commented")

    # A cell born AFTER the document took the rule is read in the row that added it,
    # and the rule revision's row is not asked about it.
    later = (
        rows
        + "        keys: K,\n        retiring: &[],\n    },\n"
        + "    // a later revision names `z` as well.\n"
        + "    DocumentShape {\n        document: FIELDS,\n        revision: 4,\n"
    )
    cz = Cell("fields", "z", "the `z` cell", "`z`", born=4)
    expect("a cell born later is found in its own row", row_findings(later, [c1, cz], rule), [])
    refused(
        "a cell born later is NOT excused by the rule revision's row",
        row_findings(later.replace("names `z`", "names `q`"), [c1, cz], rule),
        "revision 4 row does not name z",
    )
    refused(
        "a birth revision with no row is a finding",
        row_findings(rows, [cz], rule),
        "no commented `DocumentShape` row for fields revision 4",
    )

    if failures:
        print(f"json-integer-cell selftest: FAIL -- {len(failures)}")
        for f in failures:
            print(f"  {f}")
        return 1
    print("  json-integer-cell selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv:
        print(f"json-integer-cell: FAIL -- unknown argument(s) {argv}; the only option is `--selftest`")
        return 2
    return check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
