#!/usr/bin/env python3
"""Find comments whose stated BLOCKER has expired.

## The class this exists for

Eight times across R311y561-y563, a field or a family sat unimplemented behind a
comment naming its own reason, and the reason had already dissolved — sometimes
in the round that wrote it. "`z_source_info_t` is not declared by this crate"
stayed in the tree after the type was declared; "no exported `z_encoding_*`"
outlived the export by thirty rounds; "the timestamp family is a follow-up
round" outlived `z_timestamp_t` by six. Every one of them named its own blocker
in prose, and every blocker was one grep from being falsified.

That is a class, not a streak, and it is mechanically checkable: the sentence
asserts that a NAMED `z_*` / `ze_*` / `zc_*` identifier does not exist, and the
crate either defines it or does not.

## What it flags, and what it deliberately does not

A comment line is a finding when BOTH hold:

  1. it contains one of [`ABSENCE_PATTERNS`][] — a small closed set of
     negative-existence phrasings, not a general parser; and
  2. it names a `z_*` / `ze_*` / `zc_*` identifier in backticks that the SAME
     crate now defines (a `#[no_mangle]` export, a `pub struct` / `pub type`, or
     a `pub const`).

Both halves are required because either alone is noise: comments name absent
symbols legitimately (a residual list), and comments name present symbols
constantly (ordinary documentation). The finding is the CONJUNCTION — a
sentence claiming absence about something present.

It does NOT try to understand the sentence. A comment that says "`z_foo` is not
declared HERE, see the sibling crate" is a false positive, and the remedy is to
rewrite the sentence rather than to teach the lint English: a blocker worth
writing down is worth writing unambiguously.

Lines carrying a [`RETIRED_MARKERS`][] phrase are skipped — see that constant for
why, and for what the skip costs.

Exit 0 with a count when clean; exit 1 listing every finding otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# The crates whose comments this walks. The C-ABI crates are where the class
# lives: they mirror a foreign surface, so "upstream has it and we do not" is a
# sentence they write constantly and have to retire constantly.
CRATES = [
    "crates/wz-capi-c/src",
    "crates/wz-capi-pico/src",
    "crates/wz-capi-core/src",
]

# The identifier, in backticks, possibly with a trailing `*` wildcard
# (`z_encoding_*` was one of the eight). The backticks are load-bearing: they are
# how this tree writes a symbol, and requiring them keeps prose words that happen
# to start with `z` out of the match.
IDENT = r"`((?:z|ze|zc|zp)_[A-Za-z0-9_]*\*?)`"

# Negative-existence phrasings, each one BINDING the identifier as the thing
# claimed absent. The binding is what a first cut of this lint lacked, and it
# reported two findings that were both the same false positive: a sentence about
# a FIELD ("`allowed_destination` is absent from the struct (see
# [`z_put_options_t`])") names a present type incidentally, and a proximity match
# cannot tell that from a claim about the type itself.
#
# So the identifier must be the grammatical subject or object of the absence, not
# merely nearby. Each entry was taken from an ACTUAL expired blocker in this
# tree's history; the set grows by evidence rather than by imagination.
ABSENCE_PATTERNS = [
    IDENT + r"\s*(?:/\s*" + IDENT + r"\s*)?(?:family\s+)?(?:is|are)\s+not\s+declared",
    IDENT + r"\s*(?:family\s+)?(?:is|are)\s+not\s+exported",
    IDENT + r"\s*(?:family\s+)?does\s+not\s+exist",
    IDENT + r"\s*(?:family\s+)?(?:is|are)\s+absent\s+from\s+this\s+crate",
    r"no\s+exported\s+" + IDENT,
    r"does\s+not\s+(?:declare|export)\s+" + IDENT,
    r"there\s+is\s+no\s+" + IDENT,
    r"this\s+crate\s+(?:does\s+not|never)\s+\w+\s+" + IDENT,
]

# A line that RECORDS a retired blocker is not a line that states one.
#
# The second cut of this lint reported three findings and all three were of this
# shape: "it was carried opaque with the stated reason `no exported z_encoding_*`"
# — a retrospective note written by the very round that RETIRED the blocker. A
# gate that fires on its own fix notes gets turned off, so a line carrying one of
# these markers is skipped.
#
# This is a real weakening and it is worth naming: a comment reading "X is not
# declared (expired)" is skipped too. That is the right trade — such a comment is
# SELF-LABELLED as retired, so the class this exists for (a blocker asserted as
# current that is not) does not include it.
RETIRED_MARKERS = [
    r"\bexpired\b",
    r"\buntrue\b",
    r"\bno longer\b",
    r"\bwas carried\b",
    r"\bstated reason\b",
    r"\bused to\b",
    r"\bwhich was already false\b",
]

# What counts as "this crate defines it".
DEFINITION_RES = [
    re.compile(r"^\s*pub (?:unsafe )?extern \"C\" fn (\w+)", re.M),
    re.compile(r"^\s*pub struct (\w+)", re.M),
    re.compile(r"^\s*pub type (\w+)", re.M),
    re.compile(r"^\s*pub const (\w+)", re.M),
    re.compile(r"^\s*pub enum (\w+)", re.M),
]

COMMENT_RE = re.compile(r"^\s*(?://[/!]?|\*)\s?(.*)$")


def crate_definitions(crate_dir: Path) -> set[str]:
    """Every `z_*`-shaped name this crate defines."""
    names: set[str] = set()
    for path in sorted(crate_dir.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        for pattern in DEFINITION_RES:
            names.update(pattern.findall(text))
    # Macro-generated exports are real exports; the generator writes the name as
    # a macro argument rather than after `fn`, so it is picked up separately.
    for path in sorted(crate_dir.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        names.update(re.findall(r"^\s{4}((?:z|ze|zc|zp)_\w+) =>", text, re.M))
    return {n for n in names if re.match(r"^(?:z|ze|zc|zp)_", n)}


def is_defined(name: str, defined: set[str]) -> bool:
    """Whether the crate defines `name`, honouring a trailing `*` wildcard."""
    if name.endswith("*"):
        prefix = name[:-1]
        return any(d.startswith(prefix) for d in defined)
    return name in defined


def scan_crate(crate_dir: Path) -> list[tuple[str, int, str, str]]:
    """Findings as `(relpath, lineno, identifier, line)`."""
    defined = crate_definitions(crate_dir)
    absence = [re.compile(p, re.I) for p in ABSENCE_PATTERNS]
    retired = [re.compile(p, re.I) for p in RETIRED_MARKERS]
    out: list[tuple[str, int, str, str]] = []
    for path in sorted(crate_dir.rglob("*.rs")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = COMMENT_RE.match(raw)
            if not m:
                continue
            body = m.group(1)
            if any(p.search(body) for p in retired):
                continue
            for pattern in absence:
                for hit in pattern.finditer(body):
                    for ident in hit.groups():
                        if ident and is_defined(ident, defined):
                            out.append((rel, lineno, ident, body.strip()))
    return out


def main() -> int:
    findings: list[tuple[str, int, str, str]] = []
    scanned = 0
    for crate in CRATES:
        crate_dir = REPO_ROOT / crate
        if not crate_dir.is_dir():
            print(f"expired-blocker: {crate} is missing — the lint cannot report green "
                  f"on a tree it did not read", file=sys.stderr)
            return 1
        scanned += len(list(crate_dir.rglob("*.rs")))
        findings.extend(scan_crate(crate_dir))

    if not findings:
        print(f"expired-blocker lint: {scanned} file(s), 0 expired blocker(s)")
        return 0

    print(f"expired-blocker lint: {len(findings)} comment(s) assert the ABSENCE of "
          f"something this crate now DEFINES:")
    for rel, lineno, ident, body in findings:
        print(f"  {rel}:{lineno}  `{ident}` exists — {body}")
    print()
    print("  Each of these is a stated blocker that has expired. Either the work it "
          "was blocking is now unblocked, or the sentence is misleading and should "
          "say what it means. Rewrite the comment in the same commit either way.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
