#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4500 (no register item) -- a `cargo test` that names a test filter in
run-ci.sh must say how many tests it expected to run.

The items this answers, open-debt items 76 and 386, live in the agent-memory
half of the register, which has no store id for `gate_provenance_lint.py` to
resolve; this names them in prose instead.

THE DEFECT. `cargo test <filter>` exits 0 when the filter selects no test, and
so does a filter whose module a `#[cfg]` removed from the build, or a package
set whose feature unification no longer compiles the test. A run like that
reports success by silence. `_runci_guarded_test` closes it for the calls it
wraps: it asserts the libtest summary. A filtered call that is not wrapped has
no such assertion, and the decline reading after a lane sees only the SUM of a
lane's summaries, so a zero-selecting leg beside legs that ran is invisible.

THE SHAPE, read from run-ci.sh as bash. The file is lexed into simple commands
(quotes, `$(...)` captures, `( ... )` groups, heredocs, comments and `case`
patterns are honoured, so a `cargo test` inside an `echo` string or a heredoc
is text, not a command). A command RUNS A FILTERED TEST when it holds the words
`cargo test` and, after them, a positional word libtest reads as a name filter
(`--exact` does not change that). It is in the population unless it only lists
(`--list`) or only builds (`--no-run`). An array expansion such as
`"${WZ_TEST_ARGS[@]}"` is not a literal filter: the file selector it carries is
held by `count_guard_lint.py`'s filter-beside-the-array check.

A member is GUARDED when one of these holds:

  * `_runci_guarded_test` is a word of the same command, before `cargo`;
  * the command sits in a `VAR=$(...)` capture and, within the next
    COUNT_WINDOW lines, a line feeds `$VAR` by `<<<` to `_runci_passed_count`
    or to a match on a positive `test result: ok. N passed` summary -- the
    hand-written form of the same assertion.

Any other member is a FINDING, unless the exemption table below names its lane
function and filter. The table is a ratchet held both ways: a member it does not
name fails, and a row naming more members than the file holds fails too, so a
converted call must take its row with it. Every row carries its reason.

WHAT THIS DOES NOT CLAIM. That a guarded number is right -- that is
`count_guard_lint.py` and `guarded_count_gate.py`. Nor anything about cargo
calls outside run-ci.sh: a filter typed by hand at a shell has no file to lint.

Usage:
    python3 scripts/lib/unguarded_test_filter_lint.py --check
    python3 scripts/lib/unguarded_test_filter_lint.py --selftest
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNCI = REPO_ROOT / "scripts" / "run-ci.sh"

GUARD_FN = "_runci_guarded_test"
# Lines after a capture's `cargo test` within which its count must be read.
COUNT_WINDOW = 10

RESERVED = frozenset(
    {"!", "{", "}", "if", "then", "elif", "else", "do", "while", "until",
     "time", "fi", "done", "esac"}
)
# Flags that consume the next word; a bare word after one of these is its value.
VALUE_FLAGS = frozenset(
    {
        "-p", "--package", "--exclude", "--features", "-F", "--target",
        "--manifest-path", "--target-dir", "--profile", "-j", "--jobs",
        "--color", "--message-format", "-Z", "--config", "--bin", "--example",
        "--bench", "--test", "--skip", "--test-threads", "--logfile", "--format",
        "--shuffle-seed",
    }
)
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_]\w*=")
CAPTURE_RE = re.compile(r"^(?:[A-Za-z_]\w*\s+)*([A-Za-z_]\w*)=")
ARRAY_RE = re.compile(r'^"?\$\{[A-Za-z_]\w*\[@\]\}"?$')
REDIRECT_RE = re.compile(
    r"^(?:\d*|&)(?:<<<|<<-?|>>|<>|<|>)(?P<dup>&[\d-]*)?(?P<rest>.*)$"
)
TOP_FN_RE = re.compile(r"^([A-Za-z_][\w]*)\(\)\s*\{")
POSITIVE_SUMMARY_RE = re.compile(r"test result: ok\\?\.\s+(?:\[1-9\]|[1-9])")


@dataclass
class Command:
    """One simple command: its words with their offsets, and the variable
    of the `VAR=$(...)` capture it sits in, if any."""

    words: list[tuple[str, int]]
    capture: str | None


@dataclass
class _Frame:
    kind: str  # "subst" or "group"
    words: list[tuple[str, int]]
    word: str
    wstart: int
    dq: bool
    capture: str | None
    pattern_pos: bool = False


@dataclass
class _Lexer:
    text: str
    i: int = 0
    words: list[tuple[str, int]] = field(default_factory=list)
    word: str = ""
    wstart: int = -1
    dq: bool = False
    capture: str | None = None
    pattern_pos: bool = False
    stack: list[_Frame] = field(default_factory=list)
    heredocs: list[tuple[str, bool]] = field(default_factory=list)
    out: list[Command] = field(default_factory=list)

    def add(self, s: str) -> None:
        if self.wstart < 0:
            self.wstart = self.i
        self.word += s

    def flush_word(self) -> None:
        if self.wstart < 0:
            return
        w = self.word
        self.words.append((w, self.wstart))
        self.word, self.wstart = "", -1
        # `case WORD in` is followed by patterns, whose `)` closes nothing.
        if w == "in" and self._head() == "case":
            self.flush_cmd()
            self.pattern_pos = True
        elif w == "esac" and len(self.words) == 1:
            self.pattern_pos = False

    def _head(self) -> str | None:
        for w, _ in self.words:
            if w not in RESERVED:
                return w
        return None

    def flush_cmd(self) -> None:
        self.flush_word()
        if self.words:
            self.out.append(Command(self.words, self.capture))
        self.words = []

    def push(self, kind: str) -> None:
        self.stack.append(
            _Frame(kind, self.words, self.word, self.wstart, self.dq, self.capture,
                   self.pattern_pos)
        )
        if kind == "subst":
            m = CAPTURE_RE.match(self.word)
            self.capture = m.group(1) if m else None
        self.words, self.word, self.wstart, self.dq = [], "", -1, False
        self.pattern_pos = False

    def pop(self) -> None:
        self.flush_cmd()
        f = self.stack.pop()
        self.words, self.word, self.wstart, self.dq = f.words, f.word, f.wstart, f.dq
        self.capture, self.pattern_pos = f.capture, f.pattern_pos
        if f.kind == "subst":
            if self.wstart < 0:
                self.wstart = self.i
            self.word += "$()"

    def balanced(self, open_at: int, opener: str, closer: str) -> int:
        """Index just past the closer matching the opener at `open_at`."""
        depth = 0
        j = open_at
        while j < len(self.text):
            c = self.text[j]
            if c == "\\":
                j += 2
                continue
            if c == opener:
                depth += 1
            elif c == closer:
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return len(self.text)

    def heredoc_start(self) -> None:
        t = self.text
        j = self.i + 2
        strip = j < len(t) and t[j] == "-"
        if strip:
            j += 1
        while j < len(t) and t[j] in " \t":
            j += 1
        k = j
        while k < len(t) and t[k] not in " \t\n;|&<>()":
            k += 1
        delim = re.sub(r"[\"'\\]", "", t[j:k])
        self.add(t[self.i:k])
        self.heredocs.append((delim, strip))
        self.i = k

    def heredoc_skip(self) -> None:
        t = self.text
        pos = self.i + 1
        for delim, strip in self.heredocs:
            while pos < len(t):
                end = t.find("\n", pos)
                end = len(t) if end < 0 else end
                line = t[pos:end]
                pos = end + 1
                if (line.lstrip("\t") if strip else line) == delim:
                    break
        self.heredocs = []
        self.i = pos

    def run(self) -> list[Command]:
        t = self.text
        while self.i < len(t):
            c = t[self.i]
            two = t[self.i:self.i + 2]
            if c == "\\":
                if two == "\\\n":
                    self.i += 2
                    continue
                self.add(two)
                self.i += 2
                continue
            if self.dq:
                if c == '"':
                    self.dq = False
                    self.add(c)
                    self.i += 1
                elif t.startswith("$((", self.i):
                    end = self.balanced(self.i + 1, "(", ")")
                    self.add(t[self.i:end])
                    self.i = end
                elif two == "$(":
                    self.i += 2
                    self.push("subst")
                elif two == "${":
                    end = self.balanced(self.i + 1, "{", "}")
                    self.add(t[self.i:end])
                    self.i = end
                else:
                    self.add(c)
                    self.i += 1
                continue
            if c == "#" and self.wstart < 0:
                end = t.find("\n", self.i)
                self.i = len(t) if end < 0 else end
                continue
            if c == "'":
                end = t.find("'", self.i + 1)
                end = len(t) - 1 if end < 0 else end
                self.add(t[self.i:end + 1])
                self.i = end + 1
            elif c == '"':
                self.add(c)
                self.dq = True
                self.i += 1
            elif t.startswith("$((", self.i):
                end = self.balanced(self.i + 1, "(", ")")
                self.add(t[self.i:end])
                self.i = end
            elif two == "$(":
                self.i += 2
                self.push("subst")
            elif two == "${":
                end = self.balanced(self.i + 1, "{", "}")
                self.add(t[self.i:end])
                self.i = end
            elif two == "((" and self.wstart < 0:
                end = self.balanced(self.i, "(", ")")
                self.add(t[self.i:end])
                self.i = end
            elif c == "(":
                if self.wstart >= 0 and two == "()":
                    # `name() {`: a function definition, not a group.
                    self.add(two)
                    self.i += 2
                elif self.wstart >= 0 and self.word.endswith("="):
                    end = self.balanced(self.i, "(", ")")
                    self.add(t[self.i:end])
                    self.i = end
                elif self.wstart >= 0:
                    self.add(c)
                    self.i += 1
                else:
                    self.flush_cmd()
                    self.i += 1
                    self.push("group")
            elif c == ")":
                if self.pattern_pos:
                    self.words, self.word, self.wstart = [], "", -1
                    self.pattern_pos = False
                    self.i += 1
                elif self.stack:
                    self.pop()
                    self.i += 1
                else:
                    self.flush_cmd()
                    self.i += 1
            elif t.startswith("<<", self.i) and not t.startswith("<<<", self.i):
                self.heredoc_start()
            elif c in "<>" or (two in ("&>",)):
                j = self.i
                while j < len(t) and t[j] in "<>&":
                    j += 1
                while j < len(t) and (t[j].isdigit() or t[j] == "-") and t[j - 1] == "&":
                    j += 1
                self.add(t[self.i:j])
                self.i = j
            elif two in ("&&", "||", ";;", "|&"):
                self.flush_cmd()
                if two == ";;":
                    self.pattern_pos = True
                self.i += 2
            elif c in ";|&":
                self.flush_cmd()
                self.i += 1
            elif c in " \t":
                self.flush_word()
                self.i += 1
            elif c == "\n":
                self.flush_cmd()
                if self.heredocs:
                    self.heredoc_skip()
                else:
                    self.i += 1
            else:
                self.add(c)
                self.i += 1
        self.flush_cmd()
        while self.stack:
            self.pop()
        return self.out


def simple_commands(text: str) -> list[Command]:
    """Every simple command of a bash source, including those inside captures."""
    return _Lexer(text).run()


@dataclass
class TestRun:
    """A `cargo test` command and what it selects."""

    line: int
    function: str
    filters: list[str]
    guarded: bool
    lists: bool
    capture: str | None


def _unquote(w: str) -> str:
    if len(w) >= 2 and w[0] == w[-1] and w[0] in "\"'":
        return w[1:-1]
    return w


def test_runs(text: str) -> list[TestRun]:
    """Every `cargo test` command in `text` that names a literal filter."""
    starts = [0]
    for m in re.finditer("\n", text):
        starts.append(m.end())
    functions: list[str] = []
    current = "<top>"
    for ln in text.split("\n"):
        m = TOP_FN_RE.match(ln)
        if m:
            current = m.group(1)
        functions.append(current)

    def line_of(offset: int) -> int:
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    runs: list[TestRun] = []
    for cmd in simple_commands(text):
        ws = [w for w, _ in cmd.words]
        for k in range(len(ws) - 1):
            if ws[k] == "cargo" and ws[k + 1] == "test":
                break
        else:
            continue
        guarded = GUARD_FN in ws[:k]
        filters: list[str] = []
        lists = False
        args = ws[k + 2:]
        j = 0
        while j < len(args):
            a = args[j]
            r = REDIRECT_RE.match(a)
            if r:
                # `2>&1` and `>/dev/null` carry their target; a bare `>` takes
                # the next word as its own.
                j += 1 if (r.group("dup") or r.group("rest")) else 2
                continue
            if a in ("--list", "--no-run"):
                lists = True
            elif a == "--" or a == "--exact":
                pass
            elif a in VALUE_FLAGS:
                j += 1
            elif a.startswith("-") or ARRAY_RE.match(a) or a == "$()":
                pass
            else:
                filters.append(_unquote(a))
            j += 1
        if not filters:
            continue
        line = line_of(cmd.words[k][1])
        runs.append(TestRun(line, functions[line - 1], filters, guarded, lists,
                            cmd.capture))
    return runs


def counted_by_hand(lines: list[str], run: TestRun) -> bool:
    """The capture of `run` is read for a positive libtest count below it."""
    if not run.capture:
        return False
    var = re.escape(run.capture)
    feed = re.compile(r"<<<\s*\"?\$\{?" + var + r"\}?\"?")
    for ln in lines[run.line - 1:run.line - 1 + COUNT_WINDOW]:
        if feed.search(ln) and ("_runci_passed_count" in ln
                                or POSITIVE_SUMMARY_RE.search(ln)):
            return True
    return False


_PREDATES = (
    "predates this lint and nothing counts what it selects; move it under "
    "the guarded-count helper of `scripts/run-ci.sh` with the number the lane "
    "prints, then delete this row"
)
_LIST_PINNED = (
    "the same package, features and filter are listed by libtest's list mode "
    "just above it and the names compared with a pinned set, so a filter that "
    "selects nothing already fails there; this run only proves those tests pass"
)
_ONE_ARM_PINNED = (
    "a count from libtest's list mode between the two runs pins the filter in "
    "the arm with neither feature; the two runs themselves are not counted -- "
    + _PREDATES
)
_EXECUTED_SET = (
    "both runs write one log that `scripts/lib/own_space_witness_lint.py` "
    "reads in its executed mode, and it fails unless every witness derived from the source is in "
    "cargo's executed list -- a set held by name, stronger than a count"
)
_LOOPED_EXACT = (
    "one `--exact` run per name of a loop, and nothing counts what each "
    "selected; " + _PREDATES
)

# (lane function, filter words) -> (members, reason). Derived by reading
# run-ci.sh: 23 unguarded filtered runs in 14 lane functions, every other
# filtered run being wrapped, counted by hand, or a `--list`.
EXEMPT: dict[tuple[str, str], tuple[int, str]] = {
    ("layer_c1aa_cargo_test_unixsock", "locator"): (1, _PREDATES),
    ("layer_c1ab_cargo_test_vsock", "locator"): (1, _PREDATES),
    ("layer_c1ab_cargo_test_vsock", "vsock_pipeline"): (1, _PREDATES),
    ("layer_c1ac_cargo_test_quic", "locator"): (1, _PREDATES),
    ("layer_c1aj_cargo_test_quic_datagram", "locator"): (1, _PREDATES),
    ("layer_c1al_cargo_test_unixpipe", "locator"): (1, _PREDATES),
    ("layer_c1bd_locator_iface", "locator::tests"): (1, _PREDATES),
    ("layer_c1bd_locator_iface", "link_interfaces"): (1, _PREDATES),
    ("layer_c1w_cargo_test_routing_accept", "accept_loop"): (1, _PREDATES),
    ("layer_c1bi_cargo_test_pubsub_qos",
     "push_build::tests::build_push_outer_extensions"): (2, _ONE_ARM_PINNED),
    ("layer_c1bj_cargo_test_loopback_metadata_gates", "loopback_drops_"): (5, _PREDATES),
    ("layer_c1bj_cargo_test_loopback_metadata_gates",
     "push_metadata_drops_qos"): (1, _PREDATES),
    ("layer_c1bk_cargo_test_query_pub_field_gates", "pub_field"): (1, _LIST_PINNED),
    ("layer_c1bw_analyze_cli", "kind_name"): (1, _LIST_PINNED),
    ("layer_c1own_own_space_witnesses", "own_space"): (2, _EXECUTED_SET),
    ("layer_e7b_router_connect_reconcile",
     "${WZ_TEST_PREFIX}$e7b_test"): (1, _LOOPED_EXACT),
    ("layer_e7b2_router_connect_add_over_the_wire",
     "${WZ_TEST_PREFIX}$e7b2_test"): (1, _LOOPED_EXACT),
}


def grade(
    text: str, exempt: dict[tuple[str, str], tuple[int, str]]
) -> tuple[list[str], dict[str, int]]:
    """`(failures, tally)` for one run-ci.sh text against one exemption table."""
    lines = text.split("\n")
    tally = {"guarded": 0, "by_hand": 0, "listed": 0, "exempt": 0, "unguarded": 0}
    found: Counter[tuple[str, str]] = Counter()
    where: dict[tuple[str, str], list[int]] = {}
    for run in test_runs(text):
        if run.lists:
            tally["listed"] += 1
        elif run.guarded:
            tally["guarded"] += 1
        elif counted_by_hand(lines, run):
            tally["by_hand"] += 1
        else:
            key = (run.function, " ".join(run.filters))
            found[key] += 1
            where.setdefault(key, []).append(run.line)
    failures: list[str] = []
    for key, n in sorted(found.items()):
        allowed = exempt.get(key, (0, ""))[0]
        tally["exempt"] += min(n, allowed)
        if n > allowed:
            tally["unguarded"] += n - allowed
            failures.append(
                f"run-ci.sh:{','.join(map(str, where[key]))}: `cargo test` with the "
                f"filter `{key[1]}` in {key[0]} asserts no count ({n} such run(s), "
                f"{allowed} exempt). A filter that selects nothing exits 0. Wrap it: "
                f"`{GUARD_FN} <label> <N|+> cargo test ...`."
            )
    for key, (allowed, _) in sorted(exempt.items()):
        if found.get(key, 0) < allowed:
            failures.append(
                f"exemption ({key[0]}, `{key[1]}`) allows {allowed} unguarded run(s) "
                f"and run-ci.sh holds {found.get(key, 0)}. Lower the row to what is "
                f"left, or delete it: an exemption outliving its call would admit "
                f"the next unguarded filter in its place."
            )
    return failures, tally


def check() -> int:
    text = RUNCI.read_text()
    failures, tally = grade(text, EXEMPT)
    total = sum(tally[k] for k in ("guarded", "by_hand", "exempt", "unguarded"))
    print(
        f"unguarded-test-filter lint: {total} filtered `cargo test` run(s) in "
        f"run-ci.sh: {tally['guarded']} via {GUARD_FN}, {tally['by_hand']} counted "
        f"by hand, {tally['exempt']} exempt in {len(EXEMPT)} row(s), "
        f"{tally['unguarded']} unguarded; {tally['listed']} list-only"
    )
    # A lexer that stopped seeing the helper or the lists would report the
    # whole file as clean; both populations are non-empty today.
    if tally["guarded"] == 0 or tally["listed"] == 0:
        print(
            "unguarded-test-filter lint FAIL: no guarded run or no `--list` run was "
            "found. run-ci.sh holds both, so the reader has stopped reading it.",
            file=sys.stderr,
        )
        return 1
    if failures:
        print("unguarded-test-filter lint FAIL:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    return 0


_FIXTURE = r"""
layer_x() {
    # a comment naming cargo test -p p --lib commented_out
    _runci_guarded_test "X guarded (with parens)" 3 \
        cargo test -p p --lib guarded_filter --quiet || return 1
    (cd crates && cargo test -p p --features a --lib bare_filter --quiet) \
        || return 1
    echo "  X FAIL: \`cargo test -p p --lib in_a_string\` exited non-zero"
    out="$( (cd crates && cargo test -p p --lib counted --quiet) 2>&1 \
        | tee /dev/stderr )" || return 1
    n="$(_runci_passed_count <<<"$out")"
    other="$(cd crates && cargo test -p p --lib captured_uncounted --quiet 2>&1)"
    echo "$other"
    listing="$(cd crates && cargo test -p p --lib listed -- --list 2>/dev/null)"
    cat >"$stub" <<'EOF'
cargo test -p p --lib in_a_heredoc
EOF
    (cd crates && cargo test -p p --quiet) || return 1
    wz_test_args p f
    (cd crates && cargo test -p p "${WZ_TEST_ARGS[@]}" --quiet) || return 1
    _runci_leg one -- cargo test -p p --lib under_a_leg --quiet
    ( case "$mode" in
        a) echo one ;;
        *) echo two ;;
      esac
      cargo test -p p --lib after_a_case -- --exact --quiet ) || return 1
    hand="$(cd crates && cargo test -p p --lib grepped --quiet 2>&1)"
    grep -qE '^test result: ok\. [1-9][0-9]* passed' <<< "$hand" || return 1
}
layer_y() {
    (cd crates && cargo test -p p --lib exempted --quiet && cargo test -p p --lib exempted)
}
"""


def selftest() -> int:
    bad: list[str] = []
    runs = {" ".join(r.filters): r for r in test_runs(_FIXTURE)}
    expect_absent = ("commented_out", "in_a_string", "in_a_heredoc")
    for name in expect_absent:
        if name in runs:
            bad.append(f"`{name}` is text, not a command, and was read as a run")
    for name in ("guarded_filter", "bare_filter", "counted", "captured_uncounted",
                 "listed", "under_a_leg", "after_a_case", "grepped", "exempted"):
        if name not in runs:
            bad.append(f"`{name}` is a filtered run and was not read")
    if "guarded_filter" in runs and not runs["guarded_filter"].guarded:
        bad.append("a helper call with a quoted label holding parens read as unguarded")
    if "after_a_case" in runs and runs["after_a_case"].function != "layer_x":
        bad.append("a case pattern's `)` closed the subshell it sits in")
    if "listed" in runs and not runs["listed"].lists:
        bad.append("a `-- --list` run was read as one that runs tests")
    exempt = {("layer_y", "exempted"): (2, "fixture")}
    failures, tally = grade(_FIXTURE, exempt)
    flagged = sorted(f.split("filter `")[1].split("`")[0] for f in failures
                     if "filter `" in f)
    want = ["after_a_case", "bare_filter", "captured_uncounted", "under_a_leg"]
    if flagged != want:
        bad.append(f"findings {flagged}, expected {want}")
    if tally != {"guarded": 1, "by_hand": 2, "listed": 1, "exempt": 2, "unguarded": 4}:
        bad.append(f"tally {tally}")
    # The ratchet's other direction: a row allowing more than the file holds.
    stale, _ = grade(_FIXTURE, {("layer_y", "exempted"): (3, "fixture")})
    if not any("allows 3 unguarded" in f for f in stale):
        bad.append("an exemption row larger than its population was not refused")
    # And a row naming nothing at all.
    gone, _ = grade(_FIXTURE, {**exempt, ("layer_z", "gone"): (1, "fixture")})
    if not any("(layer_z, `gone`)" in f for f in gone):
        bad.append("an exemption row whose call is gone was not refused")
    for b in bad:
        print(f"unguarded-test-filter selftest FAIL: {b}", file=sys.stderr)
    if bad:
        return 1
    print("unguarded-test-filter selftest: OK (text vs command, guard, capture, "
          "list, heredoc, case, and both ratchet directions)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    return selftest() if args.selftest else check()


if __name__ == "__main__":
    sys.exit(main())
