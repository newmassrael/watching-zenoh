#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2186 (no register item) — A LIST WRITTEN IN THE SOURCE MUST NOT BE CHECKED
AGAINST ITS OWN LENGTH.

## The class, and why it needed an instrument

A test that walks a table it wrote itself and then asserts `table.len() == 6`
is comparing a list against its own length. It cannot fail: the only edit that
moves the left side is the edit that must move the right side, and the thing
the assertion was written to catch -- something arriving that the table does
not name -- moves neither.

R2185 found FIVE of these in one file pair and repaired them by deriving the
population instead. Every one had correct INTENT; one printed "a seventh must
join the table above" in the message it would never get to print. The round
closed by naming the rest of the tree as a DIRECTION rather than a finding,
because a keyword sweep cannot tell this defect from the legitimate assertion
it looks exactly like:

    assert_eq!(census.nodes().len(), 3, ...)     # a PRODUCT's count. Fine.
    assert_eq!(documents.len(), 6, ...)          # a hand-written table. Not.

Open-debt item 190 already records that a keyword sweep is structurally a
FLOOR. This is the discriminator that closes it.

## The population is derived from the BINDINGS, not from the assertions

Reading the assertion side first is the obvious approach and it is the wrong
one: it leaves an UNRESOLVED bucket -- 27 of 450 on the first measurement,
mostly destructuring `let` -- and an unresolved case has to be RED, which
makes the gate a maintenance tax on a resolver rather than a check.

So the population is the other side: every binding in tracked Rust whose
INITIALISER is a collection literal written in the source (`vec![...]`,
`[...]`, `&[...]`), whether `let`, `const` or `static`. That set is total by
construction -- a binding either is written as a literal or is not -- and it
is exactly the set that can commit the defect. A finding is one of those
bindings compared against an INTEGER LITERAL by `assert_eq!(x.len(), N)` or
`assert!(x.len() == N)`.

One alias hop is followed, because `const CARRIERS: &[T] = ALL_CARRIERS;` is
how the first real finding was spelled and a resolver that stopped at the name
would have reported nothing.

## What is deliberately NOT a finding

Comparing a source-written list against another DERIVED value
(`assert_eq!(a.len(), b.len())`, or against a walk) is the repair, not the
defect, so only an integer literal on the right counts. And a product's count
is left alone entirely: `run.misbindings().len() == 2` pins what the code
DID, which is the ordinary business of a test.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT / "crates"

# A binding whose initialiser opens a collection literal IN THE SOURCE. The
# initialiser is read to the end of its line only: what decides the class is
# what the expression OPENS with, and reading further would need a parser this
# file deliberately is not (`doc_revision`'s walkers make the same argument).
BINDING = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?"
    r"(let)\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=\n]*)?=\s*([^\n]*)$"
    r"|^[ \t]*(?:pub(?:\([^)]*\))?\s+)?"
    r"(const|static)\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:[^=\n]*=\s*([^\n]*)$",
    re.M,
)
LITERAL = re.compile(r"^&?\s*(?:alloc::)?(?:vec!\[|\[)")
# An alias: the initialiser is a bare path to another binding.
ALIAS = re.compile(r"^([A-Za-z_][A-Za-z0-9_:]*)\s*;?$")
COUNTED = re.compile(
    r"assert_eq!\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.len\(\)\s*,\s*(\d+)"
    r"|assert!\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.len\(\)\s*==\s*(\d+)"
)


def rust_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Every tracked-looking Rust source under `root`, vendored trees aside."""
    out = []
    for path in sorted(root.rglob("*.rs")):
        parts = set(path.parts)
        if "target" in parts or "vendor" in parts:
            continue
        out.append(path)
    return out


def without_line_comments(text: str) -> str:
    """`text` with whole-line `//` comments blanked, line numbering preserved.

    ⚠ MEASURED on this gate's own first repair: the round that removed the
    `CARRIERS.len() == 22` assertion QUOTED it in the doc comment explaining
    why, and the scan reported the quotation twice. A gate that reads prose as
    code reports the explanation of a defect as the defect, which is the one
    failure a lint of this kind must not have.
    Only WHOLE-LINE comments are blanked, so a `//` inside a string literal is
    never touched. The residue is a trailing comment quoting an assertion,
    which would be a false POSITIVE -- the direction that costs a reader a
    minute rather than the direction that hides a defect.
    """
    return "\n".join(
        "" if line.lstrip().startswith("//") else line for line in text.split("\n")
    )


def bindings_of(text: str) -> list[tuple[int, str, str, str]]:
    """Every binding as `(position, kind, name, initialiser)`, in file order."""
    out = []
    for m in BINDING.finditer(text):
        if m.group(1):
            out.append((m.start(), "let", m.group(2), m.group(3).strip()))
        else:
            out.append((m.start(), m.group(4), m.group(5), m.group(6).strip()))
    return out


def initialiser(
    name: str, at: int, bindings: list[tuple[int, str, str, str]]
) -> str | None:
    """The initialiser in force for `name` at byte offset `at`.

    ⚠ NEAREST PRECEDING for a `let`, and FILE-WIDE for a `const` / `static`,
    and the split is not pedantry -- it is the defect this function was
    rewritten to fix. MEASURED on 2026-08-30: a file-wide dictionary keyed by
    name reported SEVEN findings that were all the same mistake, a `let bytes =
    [..]` on line 447 answering for a `let bytes = req.encode_to_vec()` on line
    494. A statement binding is shadowed by the next one of its name; an ITEM
    is in scope for the whole file and may legally be used above its own
    definition, which is how `const CARRIERS = ALL_CARRIERS` reads.
    """
    best = None
    for pos, kind, ident, init in bindings:
        if ident != name:
            continue
        if kind == "let":
            if pos < at and (best is None or pos > best[0]):
                best = (pos, init)
        else:
            if best is None or best[1] is None:
                best = (pos, init)
    return best[1] if best else None


def is_source_literal(
    name: str, at: int, bindings: list[tuple[int, str, str, str]], depth: int = 0
) -> bool:
    init = initialiser(name, at, bindings)
    if init is None:
        return False
    if LITERAL.match(init):
        return True
    # ONE alias hop. `const CARRIERS: &[ExtCarrier] = ALL_CARRIERS;` is how the
    # first finding was spelled, and stopping at the name would have missed it.
    alias = ALIAS.match(init)
    if alias and depth == 0:
        return is_source_literal(
            alias.group(1).rsplit("::", 1)[-1], at, bindings, 1
        )
    return False


def scan(root: pathlib.Path) -> tuple[int, list[str]]:
    """(bindings examined, findings). A population of zero is the caller's FAIL."""
    examined = 0
    findings: list[str] = []
    for path in rust_files(root):
        text = without_line_comments(
            path.read_text(encoding="utf-8", errors="replace")
        )
        bindings = bindings_of(text)
        examined += sum(1 for _, _, _, init in bindings if LITERAL.match(init))
        for m in COUNTED.finditer(text):
            name = m.group(1) or m.group(3)
            count = m.group(2) or m.group(4)
            if not is_source_literal(name, m.start(), bindings):
                continue
            line = text[: m.start()].count("\n") + 1
            rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
            findings.append(
                f"{rel}:{line}: `{name}` is a list written in this source and it is "
                f"checked against the literal {count}. That compares the list to its "
                f"own length: the only edit that moves the count is the edit that "
                f"moves the list, so what the assertion was written to catch cannot "
                f"reach it. Derive the number, or compare against the set."
            )
    return examined, findings


# The fixture MARKS its own answers. Writing the expected line numbers beside
# it would be a second copy that goes stale the moment a line is inserted --
# and worse, the numbers would have been pasted from a RUN, which pins the
# gate to what it happened to do rather than to what it should do.
FINDING_MARK = "EXPECT-FINDING"
SELFTEST_FIXTURE = '''
fn a_products_count_is_not_this_gates_business() {
    let rows = build_rows();
    assert_eq!(rows.len(), 3, "what the code DID is an ordinary pin");
}
fn a_table_checked_against_its_own_length() {
    let documents = vec![("a", 1), ("b", 2)];
    assert_eq!(documents.len(), 2, "the defect");           // EXPECT-FINDING
}
const ALIASED: &[u8] = SOURCE;
const SOURCE: &[u8] = &[1, 2, 3];
fn through_one_alias_hop() {
    assert!(ALIASED.len() == 3);                            // EXPECT-FINDING
}
fn compared_against_another_derivation_is_the_repair() {
    let expected = vec!["a", "b"];
    assert_eq!(expected.len(), derived().len(), "not a literal, not a finding");
}
fn a_name_reused_later_in_the_file_answers_for_itself() {
    // THE CASE THE FIRST IMPLEMENTATION GOT WRONG, and it got it wrong on
    // seven real sites: a file-wide dictionary let the literal below answer
    // for this product. The binding in force here is the one above the
    // assertion, not the last one of that name in the file.
    let bytes = req.encode_to_vec();
    assert_eq!(bytes.len(), 4, "a product, whatever a later `bytes` holds");
}
fn the_later_binding_of_that_name() {
    let bytes = [0x00, 0xAB, 0xCD, 0xEF];
    assert_eq!(bytes.len(), 4, "and THIS one is the defect");  // EXPECT-FINDING
}
/// A DOC COMMENT THAT QUOTES THE DEFECT IS NOT THE DEFECT. The round that
/// repaired the first real finding explained itself by writing
/// `assert_eq!(quoted.len(), 22)` in prose, and the scan reported the
/// explanation. Prose is not code.
const quoted: &[u8] = &[1];
fn prose_is_not_code() {}
'''


def selftest() -> int:
    """The gate must be shown FINDING the defect and LEAVING the product alone.

    Both directions, because a checker that reported everything would satisfy
    the first arm and a checker that reported nothing would satisfy neither --
    and it is the second failure this file exists to end.
    """
    with tempfile.TemporaryDirectory() as tmp:
        home = pathlib.Path(tmp)
        (home / "src").mkdir()
        (home / "src" / "fixture.rs").write_text(SELFTEST_FIXTURE, encoding="utf-8")
        want = sorted(
            str(i)
            for i, line in enumerate(SELFTEST_FIXTURE.splitlines(), start=1)
            if FINDING_MARK in line
        )
        examined, findings = scan(home)
        if len(want) < 2 or examined < len(want):
            print(
                f"self-counted-table: SELFTEST FAIL -- the fixture marks {len(want)} "
                f"finding(s) and the scan examined {examined} source list(s); a "
                f"population it cannot see would make the arm below pass by having "
                f"nothing to look at"
            )
            return 1
        got = sorted(f.split(":")[1] for f in findings)
        if got != want:
            print(
                f"self-counted-table: SELFTEST FAIL -- the fixture marks lines {want} "
                f"and the scan reported {got}. A product's count must not be reported, "
                f"a source list must not be missed, and a comparison against another "
                f"derivation is the repair rather than the defect"
            )
            for f in findings:
                print(f"  {f}")
            return 1
    print("self-counted-table: selftest OK -- finds both shapes, spares the product")
    return 0


def main(argv: list[str]) -> int:
    # A REQUIRED mode with no default, on `relicense_spdx.py`'s rule: a program
    # whose modes read and write must not guess which was meant. Here both
    # modes read, and the reason is the same one level over -- `--selftest`
    # answers a question about the GATE and `--check` one about the tree, and a
    # green from the wrong one is the confident wrong answer.
    if len(argv) != 1 or argv[0] not in {"--check", "--selftest"}:
        print("usage: self_counted_table_gate.py --check | --selftest")
        return 2
    if argv[0] == "--selftest":
        return selftest()
    if not CRATES.is_dir():
        print(f"self-counted-table: UNREADABLE -- {CRATES} is absent")
        return 2
    examined, findings = scan(CRATES)
    if examined == 0:
        print(
            "self-counted-table: FAIL -- no source-written list was found at all, so "
            "this scan would report clean over an empty population"
        )
        return 1
    if findings:
        print(f"self-counted-table: FAIL -- {len(findings)} of {examined} source list(s)")
        for f in findings:
            print(f"  {f}")
        return 1
    print(
        f"self-counted-table: {examined} source-written list(s), none checked against "
        f"a literal count"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
