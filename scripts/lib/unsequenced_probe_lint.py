#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y570 (no register item) — reject a C probe that CONSTRUCTS and READS one object unsequenced.

## The defect this closes

`zenoh_c_pure_function_oracle.rs` shipped this at R311y568:

    printf("bytes.from_static_buf.rc=%d len=%zu\\n",
           (int)z_bytes_from_static_buf(&b5, STATIC_BUF, sizeof STATIC_BUF),
           z_bytes_len(z_bytes_loan(&b5)));

The order in which C evaluates function-call arguments is UNSPECIFIED, and gcc
evaluates right to left — so `z_bytes_len` ran against an UNINITIALISED
`z_owned_bytes_t` and printed whatever was on the stack. Both lines of this
shape printed junk on BOTH arms.

## Why an arm-vs-arm diff could not see it

The leg's gate is an equality between two stdouts, and an equality is silent
when both sides are wrong the same way. Locally the two arms' stack junk agreed
and the leg was GREEN for a full round; hosted the junk differed and the
reference arm printed a stack address (`len=140731593811125`). The defect was
found by the disagreement, not by the assertion — the assertion was satisfied
by two wrong answers.

## The rule

Inside one C full expression, if an identifier is passed as a BARE `&x`
out-parameter and the same `x` is also read through `*_loan(&x)` /
`*_loan_mut(&x)`, the two are unsequenced and the read may observe the object
before the constructor writes it. Split the constructor onto its own statement.

## What it deliberately does NOT analyse

- **Rust source.** Rust's argument evaluation order is defined left to right,
  so the same spelling in a `#[test]` is not a hazard. Only C probe sources are
  in scope: `r#"..."#` literals containing `#include`, plus any `.c` file under
  `crates/`.
- **Whether the object was already constructed by an EARLIER statement.** A
  bare `&x` that is a read-only in-parameter rather than an out-parameter is
  indistinguishable without types, so this reports the shape, not the proof.
  The remedy (one statement per constructor) is correct either way and costs
  nothing.
- Statement boundaries are taken at `;` and at the closing `)` of a `while`, `if`, `for` or
  `switch` header, so a `for(;;)` header splits into fragments. Fragments cannot match — the
  pattern needs two references to one identifier in one chunk. The header cut is what keeps a
  loop condition that constructs from being fused with a body statement that reads (R3126); the
  controls in `CONTROLS` run before any probe is read and fail the lint if the splitter drifts.

The in-scope probe set must be NON-EMPTY. A version of this that found no
probes would exit 0 forever and read as coverage; this one fails instead.

Usage:
    python3 scripts/lib/unsequenced_probe_lint.py [--verbose]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CRATES = REPO_ROOT / "crates"

# A Rust raw string literal, any hash count. The C probes in this tree are all
# written as `r#"..."#` / `r##"..."##` so a `"` inside the C source is legal.
RAW_STRING_RE = re.compile(r'r(#+)"(.*?)"\1', re.S)
# `&ident`, not `&&`, not a field access like `x.&y` (which C does not have) and
# not the tail of an identifier.
ADDR_OF_RE = re.compile(r"(?<![\w>.&])&([A-Za-z_]\w*)")
# The read form: any zenoh loan accessor taking the address of the object.
LOAN_RE = re.compile(r"_loan(?:_mut)?\s*\(\s*&([A-Za-z_]\w*)")
# Used to decide whether a given `&x` sits directly inside a loan call.
LOAN_TAIL_RE = re.compile(r"_loan(?:_mut)?\s*\(\s*$")


def c_probe_sources() -> list[tuple[Path, int, str]]:
    """Every C probe source in the tree, as (file, line offset, text)."""
    found: list[tuple[Path, int, str]] = []
    for path in sorted(CRATES.rglob("*.rs")):
        # RELATIVE (R2338): whether an ABSOLUTE test means the same thing is a
        # fact about where the tree happens to sit, not about this walk.
        if "target" in path.relative_to(CRATES).parts:
            continue
        text = path.read_text(errors="ignore")
        if "#include" not in text:
            continue
        for match in RAW_STRING_RE.finditer(text):
            body = match.group(2)
            if "#include" not in body:
                continue
            line = text[: match.start()].count("\n") + 1
            found.append((path, line, body))
    for path in sorted(CRATES.rglob("*.c")):
        if "target" in path.relative_to(CRATES).parts:
            continue
        found.append((path, 1, path.read_text(errors="ignore")))
    return found


# The keywords whose parenthesised header is a controlling expression.
CONTROL_RE = re.compile(r"\b(?:while|if|for|switch)\s*\(")


def statements(source: str) -> list[tuple[int, str]]:
    """(offset, text) of each C statement, cut at `;` and at the close of a control header.

    The controlling expression of `while`, `if`, `for` and `switch` is a full expression with a
    sequence point at its closing `)`, and everything in the body that follows is sequenced after
    it. Cutting at `;` alone fused `while (next(&it, &slice)) {` with the first statement of its
    body into one chunk, so a loop that constructs in its condition and reads in its body was
    reported as an unsequenced pair (R3126: the two-slice iterator probe, red on hosted C0).
    A header with no brace after it (`while (c) stmt;`) is cut the same way, which is also right.
    """
    cuts = {m.end() for m in re.finditer(";", source)}
    for m in CONTROL_RE.finditer(source):
        depth = 0
        i = m.end() - 1  # the `(` that opens the header
        while i < len(source):
            if source[i] == "(":
                depth += 1
            elif source[i] == ")":
                depth -= 1
                if depth == 0:
                    cuts.add(i + 1)
                    break
            i += 1
    out: list[tuple[int, str]] = []
    prev = 0
    for cut in sorted(cuts | {len(source)}):
        out.append((prev, source[prev:cut]))
        prev = cut
    return out


def violations_in(source: str) -> list[tuple[int, str, str]]:
    """(line within source, identifier, the offending full expression)."""
    out: list[tuple[int, str, str]] = []
    for start, chunk in statements(source):
        if "&" not in chunk:
            continue
        loaned = set(LOAN_RE.findall(chunk))
        if not loaned:
            continue
        bare: set[str] = set()
        for match in ADDR_OF_RE.finditer(chunk):
            if LOAN_TAIL_RE.search(chunk[: match.start()]):
                continue
            bare.add(match.group(1))
        for ident in sorted(bare & loaned):
            line = source[:start].count("\n") + 1
            out.append((line, ident, " ".join(chunk.split())[:200]))
    return out


# (name, C source, whether it must be reported). The lint runs these before it reads any probe, so
# a statement splitter that stops seeing the real hazard, or starts seeing a loop that is fine, is
# red here and not only on a probe that happens to exercise it.
CONTROLS: list[tuple[str, str, bool]] = [
    (
        "the R311y568 shape: construct and read in one argument list",
        'printf("%d %zu", (int)z_bytes_from_static_buf(&b5, B, 1), z_bytes_len(z_bytes_loan(&b5)));',
        True,
    ),
    (
        "construct and read inside one control header",
        "if (z_try(&v) == 0 && z_v_len(z_v_loan(&v))) { go(); }",
        True,
    ),
    (
        "construct in a loop condition, read in its body",
        "while (z_it_next(&it, &s)) {\n  const z_loaned_slice_t* l = z_view_slice_loan(&s);\n  use(l);\n}",
        False,
    ),
    (
        "construct in a for step, read in its body",
        "for (z_a(&a); z_ok(&a); z_step(&a)) {\n  use(z_a_loan(&a));\n}",
        False,
    ),
    (
        "construct on one statement, read on the next",
        "z_make(&x);\nz_len(z_x_loan(&x));",
        False,
    ),
]


def controls_hold() -> list[str]:
    """The controls whose verdict is not the one they declare; empty means the splitter is sound."""
    bad = [
        name
        for name, source, expected in CONTROLS
        if bool(violations_in(source)) != expected
    ]
    return bad


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    broken = controls_hold()
    if broken:
        print(
            "Layer C0 FAIL: the unsequenced-probe lint's own controls disagree with it: "
            + "; ".join(broken),
            file=sys.stderr,
        )
        return 1

    probes = c_probe_sources()
    if not probes:
        print(
            "Layer C0 FAIL: the unsequenced-probe lint found NO C probe source. "
            "Its in-scope set is empty, so a pass would mean nothing.",
            file=sys.stderr,
        )
        return 1

    findings: list[str] = []
    for path, line_offset, body in probes:
        rel = path.relative_to(REPO_ROOT)
        if args.verbose:
            print(f"  probe {rel}:{line_offset} ({body.count(chr(10)) + 1} lines)")
        for line, ident, expr in violations_in(body):
            findings.append(
                f"  {rel}:{line_offset + line - 1}: `{ident}` is passed as a bare "
                f"`&{ident}` out-parameter AND read through a loan accessor in the "
                f"SAME full expression.\n    {expr}"
            )

    print(
        f"unsequenced-probe lint: {len(probes)} C probe source(s) scanned, "
        f"{len(findings)} finding(s)"
    )
    if findings:
        print(
            "\nLayer C0 FAIL: a C probe constructs and reads one object in an "
            "UNSEQUENCED pair.\nC does not order function-call arguments; gcc "
            "evaluates them right to left, so the\nread can observe the object "
            "before the constructor writes it. An arm-vs-arm diff\nCANNOT see "
            "this — both arms print stack junk and an equality between two wrong\n"
            "answers is green (R311y568 shipped exactly that, and only the hosted "
            "runner's\ndifferent stack junk exposed it).\n\nFix: give the "
            "constructor its own statement, then print.\n",
            file=sys.stderr,
        )
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
