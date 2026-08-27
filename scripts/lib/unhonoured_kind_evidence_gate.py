#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2150 (no register item) — a key's KIND of unhonoured can be wrong, and the
four checks guarding the split cannot ask whether it is right.

The citation reads `no register item` for the reason `config_key_fixture_gate.py`
gives for its own: the item this closes — unregistered open-debt item 539 — lives
in the agent-memory register, which has no store id for `gate_provenance_lint.py`
to resolve. The item is named in prose throughout this header.

## The defect

R2148 split `UNHONOURED_UPSTREAM_CONFIG_KEYS` into two lists: the keys wz
genuinely cannot act on (`UNHONOURED_BEYOND_WZ`) and the keys wz ALREADY ACTS ON
whose spelling its reader was never taught (`UNHONOURED_READER_GAP`). The
difference is the whole of "what is not supported" — the first is a feature
nobody built, which fails visibly; the second is a file an operator already has
that looks like it works and does nothing.

`every_unhonoured_key_says_which_kind_of_unhonoured_it_is` makes that split
TOTAL, DISJOINT, un-orphaned, and forces the two sizes to sum. Not one of those
four asks whether a row is in the RIGHT list. So a `BEYOND` row that becomes a
reader gap — because wz grows the capability — reds nothing, ever.

Measured on the first run of this gate, with the two lists exactly as R2148 left
them: THREE of the seventy-five `BEYOND` rows were already reader gaps.

  * `connect/timeout_ms` — implemented by `StaticConnectRetry::timeout_ms`,
    which spells the key in its own doc and carries upstream's `-1` / `0` /
    positive reading, while sitting under a group sentence saying wz's
    session-open path implements no `connect/*` behaviour at all — next to
    `connect/retry`, which wz HONOURS.
  * `downsampling` and `low_pass_filter` — both are rules on wz's composable
    `InterceptorChain`, under a group sentence saying wz would need "an
    interceptor chain configured from the same file".

## The rule item 539 pre-refuted

"wz's source names the key, therefore wz honours it" is FALSE, and the item
measured three counter-reasons before it was filed. This sweep found five in
total, which is why the answer is not one predicate but a DECLARED KIND per row,
each with its own machine-checked anchor. The kinds and their anchors live in
`UNHONOURED_CITATION_KINDS` / `UNHONOURED_CITATION_LEDGER`; this file evaluates
them.

## What it derives rather than declares

Nothing here carries a copy of anything.

  * the three key lists and the ledger come from the Rust source, comments
    stripped (`deepenable_audit.rust_const`, the reader repaired after a regex
    counted quoted phrases inside an array's own rationales as entries);
  * the KIND VOCABULARY comes from `UNHONOURED_CITATION_KINDS`, so a kind this
    file cannot dispatch is a hard failure rather than a silently skipped row;
  * the ENUMERATOR EXCLUSION is derived from the source too. A file that
    enumerates the surface — the definition site, and the drop-in test that
    imports the list — spells every key, which would make every key "cited" and
    the whole population meaningless (R2148 hit exactly this and had to strike
    the enumerator by hand). The rule is: a file whose CODE names any
    `UNHONOURED_*` constant gets its keys FROM the list, so its occurrences are
    enumeration, not citation. Comments are stripped before that test on
    purpose — a doc comment that mentions the list by name is still a citing
    site, and two of this round's own additions are exactly that shape.

Every anchor is a HARD FAIL when it does not match, and so is an empty
population at any step. A gate that cannot find its subject must not report on
it.

## What this cannot do, stated rather than hidden

The population is the keys wz NAMES, not the capabilities wz HAS. A capability
grown under a spelling of wz's own produces no citation and no row —
`low_pass_filter` was such a case until this round, and it was found by reading
a group sentence, not by this sweep. That residue is open-debt item 540. What
the ledger buys is that a wrong kind now costs a symbol that must exist in wz's
code and a list the row must sit in, instead of a sentence.

Usage:
    python3 scripts/lib/unhonoured_kind_evidence_gate.py [--verbose]
    python3 scripts/lib/unhonoured_kind_evidence_gate.py --selftest
"""

from __future__ import annotations

import argparse
import bisect
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rust_comments  # noqa: E402  -- after the path insert that finds it

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "crates" / "wz-runtime-tokio" / "src" / "zenoh_config.rs"

# The three `&[&str]` lists this gate reads. `UNHONOURED_UPSTREAM_CONFIG_KEYS`
# is the whole; the other two are the split whose KINDS are the subject.
WHOLE = "UNHONOURED_UPSTREAM_CONFIG_KEYS"
BEYOND = "UNHONOURED_BEYOND_WZ"
READER_GAP = "UNHONOURED_READER_GAP"

# A citation is the key spelled as a path. Upstream writes its keys with `.` and
# this tree's own reader with `/`, and BOTH spellings occur in wz's prose — a
# sweep that knows only one under-reports by however many spellings the source
# uses, which is the R2140 lesson in its smallest form.
SEPARATORS = ("/", ".")


def _const_body(src: str, name: str, shape: str) -> str:
    m = re.search(
        r"(?:pub )?const " + re.escape(name) + r": " + shape + r" = &\[(.*?)\n\];",
        src,
        re.S,
    )
    if not m:
        raise SystemExit(
            f"unhonoured-kind-evidence: FAIL -- {name} not found in the reader's "
            f"source. A gate that cannot find its subject must not report on it."
        )
    return rust_comments.strip_comments(m.group(1))


def parse_str_list(src: str, name: str) -> list[str]:
    """Read a `&[&str]` constant. Comments stripped FIRST (R2083's miscount)."""
    return re.findall(r'"([^"]+)"', _const_body(src, name, r"&\[&str\]"))


def parse_ledger(src: str) -> list[tuple[str, str, str]]:
    """Read `UNHONOURED_CITATION_LEDGER` as `(key, kind, anchor)` triples.

    rustfmt breaks a long row across four lines, so the pattern spans newlines
    rather than assuming one row per line — a line-anchored reader would have
    silently dropped the eight widest rows, which is under-reporting, the one
    defect a gate must not have.
    """
    body = _const_body(src, "UNHONOURED_CITATION_LEDGER", r"&\[\(&str, &str, &str\)\]")
    return re.findall(
        r'\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,?\s*\)', body, re.S
    )


def enumerating_consts(src: str) -> list[str]:
    """Every `UNHONOURED_*` constant the reader defines.

    DERIVED, not listed: a fifth constant added later joins the exclusion by
    existing, which is the difference between a rule and an inventory.
    """
    return sorted(set(re.findall(r"(?:pub )?const (UNHONOURED_[A-Z0-9_]+)\s*:", src)))


def is_enumerator(text: str, const_names: list[str]) -> bool:
    """Does this file get its keys FROM the list rather than name them?

    Comments are stripped first. A doc comment that says "this key is carried in
    `UNHONOURED_READER_GAP`" is a CITING site — it is wz asserting the mapping,
    which is the evidence this gate is looking for — while code that reads the
    constant is an enumeration of the whole surface.
    """
    code = rust_comments.strip_comments(text)
    return any(name in code for name in const_names)


_WORD_OR_SEP = re.compile(r"[A-Za-z0-9_./]")
_WORD = re.compile(r"[A-Za-z0-9_]")


def _boundary_ok(text: str, i: int, j: int) -> bool:
    """Is `text[i:j]` a whole path token rather than part of a longer one?

    This is what keeps `scouting.gossip.autoconnect` from matching inside
    `scouting.gossip.autoconnect_strategy`, and what keeps a key from matching
    as the TAIL of a longer path — `transport/unicast/accept_timeout` must not
    be found inside a hypothetical `x/transport/unicast/accept_timeout`.
    """
    before = text[i - 1] if i else " "
    after = text[j] if j < len(text) else " "
    if _WORD_OR_SEP.match(before):
        return False
    if _WORD.match(after):
        return False
    # A separator immediately followed by a word means the match is a PREFIX of
    # a deeper path, which is a different key.
    if after in SEPARATORS and j + 1 < len(text) and _WORD.match(text[j + 1]):
        return False
    return True


def _token_hit(line: str, form: str) -> bool:
    """Is `form` present in `line` as a whole path token?"""
    pos = line.find(form)
    while pos >= 0:
        if _boundary_ok(line, pos, pos + len(form)):
            return True
        pos = line.find(form, pos + 1)
    return False


def citations_all(
    keys: list[str], files: dict[str, str]
) -> dict[str, list[tuple[str, int, str]]]:
    """Every (path, line number, line) where wz's source spells each key.

    ONE regex pass per file, over an alternation of every spelling of every key,
    rather than a scan per key per line: the naive shape was measured at minutes
    across eight hundred files, which is not a static gate. Longest form first
    so `scouting.gossip.autoconnect_strategy` is matched as itself rather than
    as `scouting.gossip.autoconnect` with a tail.
    """
    forms: dict[str, str] = {}
    for k in keys:
        for form in {k} | {k.replace("/", sep) for sep in SEPARATORS}:
            forms[form] = k
    out: dict[str, list[tuple[str, int, str]]] = {k: [] for k in keys}
    for path, text in sorted(files.items()):
        present = [f for f in forms if f in text]
        if not present:
            continue
        lines = text.splitlines()
        starts: list[int] = []
        at = 0
        for line in lines:
            starts.append(at)
            at += len(line) + 1
        for form in present:
            key = forms[form]
            hits = out[key]
            pos = text.find(form)
            while pos >= 0:
                if _boundary_ok(text, pos, pos + len(form)):
                    i = bisect.bisect_right(starts, pos) - 1
                    site = (path, i + 1, lines[i] if 0 <= i < len(lines) else "")
                    # A key spelled twice on one line is ONE site. The counts
                    # below are REPORTED, so an inflated one is a wrong number
                    # in the message someone reads to find the site.
                    if not hits or hits[-1][:2] != site[:2]:
                        hits.append(site)
                pos = text.find(form, pos + 1)
    for key in out:
        out[key].sort()
    return out


def citations(key: str, files: dict[str, str]) -> list[tuple[str, int, str]]:
    """Every (path, line number, line) where wz's source spells `key`."""
    return citations_all([key], files)[key]


def audit(src: str, files: dict[str, str]) -> tuple[list[str], list[str]]:
    """The whole judgement, as (failures, report lines).

    Pure over its two inputs so `--selftest` can drive it with fixtures: a gate
    whose own arms can only be exercised against the real tree is a gate whose
    arms are never exercised.
    """
    failures: list[str] = []
    report: list[str] = []

    consts = enumerating_consts(src)
    if len(consts) < 3:
        failures.append(
            f"only {len(consts)} `UNHONOURED_*` constant(s) found in the reader's "
            f"source ({consts}) — the enumerator exclusion is derived from that "
            f"set, and a broken derivation would let the definition site count "
            f"as a citation of every key"
        )
        return failures, report

    whole = parse_str_list(src, WHOLE)
    beyond = parse_str_list(src, BEYOND)
    gap = parse_str_list(src, READER_GAP)
    kinds = parse_str_list(src, "UNHONOURED_CITATION_KINDS")
    ledger = parse_ledger(src)

    for name, population in (
        (WHOLE, whole),
        (BEYOND, beyond),
        (READER_GAP, gap),
        ("UNHONOURED_CITATION_KINDS", kinds),
        ("UNHONOURED_CITATION_LEDGER", ledger),
    ):
        if not population:
            failures.append(f"{name} parsed EMPTY — a zero population reports green")
    if failures:
        return failures, report

    swept = {p: t for p, t in files.items() if not is_enumerator(t, consts)}
    excluded = sorted(set(files) - set(swept))
    if not excluded:
        failures.append(
            "no file was excluded as an enumerator — the definition site itself "
            "spells every key, so a sweep that keeps it reports every key as "
            "cited and this gate would grade nothing"
        )
    if not swept:
        failures.append("no file left to sweep after the enumerator exclusion")
    if failures:
        return failures, report

    cited = {k: v for k, v in citations_all(whole, swept).items() if v}
    if not cited:
        failures.append(
            "no unhonoured key is named anywhere in wz's source — the sweep "
            "found nothing to grade, which is a broken sweep, not a clean tree"
        )
        return failures, report

    rows = {key: (kind, anchor) for key, kind, anchor in ledger}

    # 1. every cited key carries a verdict.
    for key in sorted(cited):
        if key not in rows:
            where = ", ".join(f"{p}:{n}" for p, n, _ in cited[key][:3])
            failures.append(
                f"{key}: wz's source names it ({len(cited[key])} site(s): {where}) "
                f"and UNHONOURED_CITATION_LEDGER does not say why that naming is "
                f"not proof wz honours it"
            )

    # 2. no verdict about a key nothing names.
    for key in sorted(rows):
        if key not in cited:
            failures.append(
                f"{key}: carries a citation row and wz's source does not name it "
                f"— a verdict about evidence that is gone"
            )

    # 3. each verdict's own anchor.
    code = {p: rust_comments.strip_comments(t) for p, t in swept.items()}
    for key in sorted(rows):
        if key not in cited:
            continue
        kind, anchor = rows[key]
        if kind not in kinds:
            failures.append(
                f"{key}: kind `{kind}` is not one of {kinds} — this gate "
                f"dispatches on that word and will not guess"
            )
        elif kind in ("wz-has-it", "not-this-key"):
            holders = sorted(p for p, c in code.items() if anchor in c)
            if not holders:
                failures.append(
                    f"{key}: kind `{kind}` names `{anchor}`, and no wz source "
                    f"file has it in CODE. Prose is not a mechanism — an anchor "
                    f"that survives only in a comment is the shape this row is "
                    f"supposed to rule out"
                )
        elif kind == "asserted-ignored":
            lines = [
                f"{p}:{n}" for p, n, line in cited[key] if anchor.lower() in line.lower()
            ]
            if not lines:
                failures.append(
                    f"{key}: kind `asserted-ignored` claims a citing line also "
                    f"says `{anchor}`, and none of the {len(cited[key])} citing "
                    f"line(s) does"
                )
        elif kind == "foreign-node-config":
            citing_files = sorted({p for p, _, _ in cited[key]})
            without = [p for p in citing_files if anchor not in swept[p]]
            if without:
                failures.append(
                    f"{key}: kind `foreign-node-config` claims every citing file "
                    f"drives a `{anchor}`, and {len(without)} does not: "
                    f"{', '.join(without)}"
                )

    # The breakdown, per kind, with a floor on each. A kind with no LIVE row is a
    # branch of this dispatch nobody has ever run, and the total hides that.
    for kind in kinds:
        members = sorted(k for k, (kd, _) in rows.items() if kd == kind and k in cited)
        if not members:
            failures.append(
                f"citation kind `{kind}` has no cited row — an unexercised "
                f"branch is not coverage"
            )
        report.append(f"  {kind}: {len(members)} key(s) {members}")

    uncited = sorted(k for k in whole if k not in cited)
    report.append(
        f"  {len(uncited)} unhonoured key(s) wz's source never names — this gate "
        f"says NOTHING about those; a capability under a spelling of wz's own "
        f"leaves no citation (open-debt item 540)"
    )
    report.insert(
        0,
        f"unhonoured-kind-evidence: {len(whole)} unhonoured key(s) "
        f"({len(beyond)} beyond wz, {len(gap)} reader gap); {len(swept)} file(s) "
        f"swept, {len(excluded)} excluded as enumerator(s); {len(cited)} key(s) "
        f"named by wz's source, {len(ledger)} verdict(s) recorded",
    )
    return failures, report


# ─── selftest ───────────────────────────────────────────────────────
#
# Every arm below MUTATES one thing off a baseline that passes, and each is a
# mutation the gate is claimed to catch. The baseline is not a stub: it carries
# a real enumerator file, a citing doc comment that NAMES a constant (the shape
# that must NOT be excluded), and one member of every kind — so an arm that
# passes for the wrong reason has to get past a fixture with the same shape as
# the tree.

_FIXTURE_SRC = '''
pub const UNHONOURED_UPSTREAM_CONFIG_KEYS: &[&str] = &[
    "aa/bb",
    "cc/dd",
    "ee",
    "ff/gg",
    "hh/ii",
];

pub const UNHONOURED_BEYOND_WZ: &[&str] = &[
    // "aa/bb" is quoted HERE, in a comment, to keep the reader honest.
    "cc/dd",
    "ee",
    "ff/gg",
    "hh/ii",
];

pub const UNHONOURED_READER_GAP: &[&str] = &[
    "aa/bb",
];

pub const UNHONOURED_CITATION_KINDS: &[&str] = &[
    "asserted-ignored",
    "foreign-node-config",
    "not-this-key",
    "wz-has-it",
];

pub const UNHONOURED_CITATION_LEDGER: &[(&str, &str, &str)] = &[
    ("aa/bb", "wz-has-it", "set_aa_bb"),
    ("cc/dd", "not-this-key", "OtherThing"),
    ("ee", "asserted-ignored", "ignored"),
    (
        "ff/gg",
        "foreign-node-config",
        "zenohd",
    ),
];
'''

_FIXTURE_FILES = {
    # The definition site. Excluded because its CODE names the constants.
    "src/reader.rs": _FIXTURE_SRC,
    # An enumerator: it imports the list. Spells every key, and must not count.
    "tests/enumerate.rs": (
        "use crate::UNHONOURED_UPSTREAM_CONFIG_KEYS;\n"
        'fn all() { let _ = ["aa/bb", "cc/dd", "ee", "ff/gg", "hh/ii"]; }\n'
    ),
    # The capability, naming its key in a doc comment AND naming a constant
    # there — the shape that must survive the exclusion.
    "src/gossip.rs": (
        "/// Answers `aa.bb`; carried in `UNHONOURED_READER_GAP` until the\n"
        "/// reader learns it.\n"
        "pub fn set_aa_bb() {}\n"
    ),
    # A different mechanism that happens to match the key's default.
    "src/other.rs": (
        "/// Matches zenoh's `cc.dd` default, by a mechanism of our own.\n"
        "pub struct OtherThing;\n"
    ),
    # wz's own test asserting the key is ignored.
    "src/args.rs": 'fn t() { assert_eq!(out.ignored, vec!["ee"]); }\n',
    # An interop leg configuring the OTHER implementation.
    "tests/interop.rs": (
        'fn t() { cmd.arg("ff/gg:1"); run("zenohd"); }\n'
    ),
}


def _selftest() -> int:
    def run(name: str, src: str, files: dict[str, str], want_fail: str | None) -> bool:
        failures, _ = audit(src, files)
        if want_fail is None:
            ok = not failures
            print(f"  {'ok  ' if ok else 'FAIL'} {name}: expected clean")
            if not ok:
                for f in failures:
                    print(f"        {f}")
            return ok
        ok = any(want_fail in f for f in failures)
        print(f"  {'ok  ' if ok else 'FAIL'} {name}: expected a failure naming {want_fail!r}")
        if not ok:
            print(f"        got: {failures}")
        return ok

    arms: list[tuple[str, str, dict[str, str], str | None]] = []
    arms.append(("baseline", _FIXTURE_SRC, dict(_FIXTURE_FILES), None))

    # A cited key with no verdict.
    f = dict(_FIXTURE_FILES)
    f["src/extra.rs"] = "/// Mentions `hh.ii` in passing.\npub fn x() {}\n"
    arms.append(("cited key with no verdict", _FIXTURE_SRC, f, "hh/ii"))

    # A verdict about a key nothing names.
    src = _FIXTURE_SRC.replace(
        '    ("cc/dd", "not-this-key", "OtherThing"),',
        '    ("cc/dd", "not-this-key", "OtherThing"),\n    ("hh/ii", "not-this-key", "OtherThing"),',
    )
    arms.append(("verdict for an unnamed key", src, dict(_FIXTURE_FILES), "hh/ii"))

    # `wz-has-it` whose anchor is gone from the code.
    src = _FIXTURE_SRC.replace('"wz-has-it", "set_aa_bb"', '"wz-has-it", "set_zz_zz"')
    arms.append(("wz-has-it anchor absent", src, dict(_FIXTURE_FILES), "set_zz_zz"))

    # `wz-has-it` whose anchor survives ONLY in prose. The needle sits inside the
    # span a comment-blind reader would have swallowed whole.
    f = dict(_FIXTURE_FILES)
    f["src/gossip.rs"] = (
        "/// Answers `aa.bb`; carried in `UNHONOURED_READER_GAP`. The mechanism\n"
        "/// used to be `set_aa_bb`, which no longer exists.\n"
        "pub fn something_else() {}\n"
    )
    arms.append(("wz-has-it anchor only in prose", _FIXTURE_SRC, f, "set_aa_bb"))

    # `not-this-key` whose anchor is gone.
    src = _FIXTURE_SRC.replace('"not-this-key", "OtherThing"', '"not-this-key", "GoneThing"')
    arms.append(("not-this-key anchor absent", src, dict(_FIXTURE_FILES), "GoneThing"))

    # `asserted-ignored` where no citing LINE carries the word.
    f = dict(_FIXTURE_FILES)
    f["src/args.rs"] = 'fn t() {\n    assert_eq!(out.ignored,\n        vec!["ee"]);\n}\n'
    arms.append(("asserted-ignored word off the citing line", _FIXTURE_SRC, f, "asserted-ignored"))

    # `foreign-node-config` where ONE citing file lacks the marker — the half a
    # gate asking "any file" would miss.
    f = dict(_FIXTURE_FILES)
    f["src/local.rs"] = '/// We honour `ff/gg` here, actually.\npub fn y() {}\n'
    arms.append(("foreign-node-config with a local citing file", _FIXTURE_SRC, f, "src/local.rs"))

    # A kind the dispatch does not know must FAIL, not be skipped.
    src = _FIXTURE_SRC.replace('"cc/dd", "not-this-key"', '"cc/dd", "probably-fine"')
    arms.append(("unknown kind", src, dict(_FIXTURE_FILES), "probably-fine"))

    # A kind with no cited row is an unexercised branch.
    src = _FIXTURE_SRC.replace('    ("ee", "asserted-ignored", "ignored"),\n', "")
    arms.append(("kind with no member", src, dict(_FIXTURE_FILES), "asserted-ignored"))

    # The enumerator exclusion itself: with nothing excluded, every key looks
    # cited and the population is meaningless.
    f = {"tests/enumerate.rs": _FIXTURE_FILES["tests/enumerate.rs"].replace(
        "use crate::UNHONOURED_UPSTREAM_CONFIG_KEYS;\n", ""
    )}
    arms.append(("nothing excluded as enumerator", _FIXTURE_SRC, f, "enumerator"))

    # An empty ledger passes every per-row loop by having no rows.
    src = re.sub(
        r"pub const UNHONOURED_CITATION_LEDGER: &\[\(&str, &str, &str\)\] = &\[.*?\n\];",
        "pub const UNHONOURED_CITATION_LEDGER: &[(&str, &str, &str)] = &[\n];",
        _FIXTURE_SRC,
        flags=re.S,
    )
    arms.append(("empty ledger", src, dict(_FIXTURE_FILES), "EMPTY"))

    print(f"unhonoured-kind-evidence selftest: {len(arms)} arm(s)")
    passed = sum(1 for a in arms if run(*a))
    print(f"  {passed}/{len(arms)} arm(s) behaved as claimed")
    return 0 if passed == len(arms) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return _selftest()

    tracked = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "*.rs"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    if not tracked:
        print(
            "unhonoured-kind-evidence: FAIL -- `git ls-files '*.rs'` came back "
            "empty; the sweep has no population",
            file=sys.stderr,
        )
        return 1
    files: dict[str, str] = {}
    for rel in tracked:
        try:
            files[rel] = (REPO_ROOT / rel).read_text()
        except (OSError, UnicodeDecodeError) as exc:  # pragma: no cover - unreadable tree
            print(f"unhonoured-kind-evidence: FAIL -- cannot read {rel}: {exc}", file=sys.stderr)
            return 1

    failures, report = audit(SOURCE.read_text(), files)

    for line in report:
        print(line)
    if args.verbose:
        src = SOURCE.read_text()
        consts = enumerating_consts(src)
        swept = {p: t for p, t in files.items() if not is_enumerator(t, consts)}
        for key, kind, anchor in parse_ledger(src):
            sites = citations(key, swept)
            print(f"  {key} [{kind} <- {anchor}]")
            for p, n, _ in sites[:6]:
                print(f"      {p}:{n}")
            if len(sites) > 6:
                print(f"      ... {len(sites) - 6} more site(s)")

    if failures:
        print("unhonoured-kind-evidence FAIL:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
