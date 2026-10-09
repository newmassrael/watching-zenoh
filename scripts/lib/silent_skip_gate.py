#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
r"""R3171 (no register item) -- a test that RUNS BY DEFAULT must not pass by
skipping a fixture its lane requires.

The citation is `no register item` for the reason `debt_plane_census.py` gives
for its own: the item this answers for -- unregistered open-debt item 776 --
lives in an agent-memory register outside this repository, which has no store
id for `gate_provenance_lint.py` to resolve. Naming it in prose here and
`no register item` in the citation is the honest pair.

## What generated the defect

`plugin.rs` carried `require_example()`: when the example cdylib was absent it
printed `skip: ... not built` and returned `None`, and each of five tests then
`return`ed. R2675 deliberately re-created a regression to check its new witness
and the witness PASSED -- not because the repair was right but because nothing
ran. The only signal was `finished in 0.00s`. `dynamic_volume.rs` (nine sites)
and `plugin_plane.rs` (two) carried the same shape, so the register's "six
tests in plugin.rs" named who noticed, not the population.

## Why the population is the tests that run BY DEFAULT

An `#[ignore]`d test runs only when a lane asks for it with `--ignored`, and
this tree's lanes decide, BEFORE they ask, whether the fixture is there:
`_z_unavailable`, `_pico_cli_unavailable` and the other `WZ_*_REQUIRE` branches
turn an absent oracle into a lane failure on the job that provisions it
(`armed_skip_guard.py` grades that half over the shell). The in-test skip behind
such a lane is a second line, and it was measured at 50 sites of the integration
corpus -- all behind a lane preflight. Making them carry a second switch would
duplicate the lane's and move nothing.

A test with NO `#[ignore]` has no lane in front of it. `cargo test` anywhere runs
it, the fixture is not owed by anyone, and skipping reads as a pass. That is the
defect, and the three modules above are all of it: their tests are plain `#[test]`.
Where a lane builds the fixture first (Layer C1bp, C1bv) the lane is the party that
OWES it, so the lane must be able to say so -- which is the door below.

## The rule

A SKIP SITE is a `print!`-family call whose first string literal begins with
`skip` and which is immediately followed by `return` or `None` -- the shape of
"say it, then step over the test's subject". A skip site is IN SCOPE when the fn
holding it is, or is reachable by name (within the crate) from, a test that is not
`#[ignore]`d -- or is reachable from no test at all, which is the conservative
reading of a skip nobody can attribute. An in-scope skip site must reach a DOOR: a
`"<WORD>_REQUIRE"` string literal, in the fn itself or in a fn it calls, because
that literal is what lets a lane turn the skip into a failure.

Two more bindings, each derived and neither a list:

  * the door is ARMED by something. Its variable must be set by `scripts/run-ci.sh`
    on a non-comment line (`local -x NAME=`, `export NAME=`, `NAME=1 cargo`) or by a
    workflow's `env:` mapping (`NAME: "1"`, the way a job that provisions an oracle
    arms it). A door no lane arms is a skip with a label on it.
  * a non-ignored test that bails out with `let Some(..) = helper(..) else { return; }`
    is skipping on whatever `helper` says, so `helper` (resolved by name within the
    crate, `Option`-returning) must itself hold a skip site. A helper that returns
    `None` and says nothing is the silent form of the defect, and is refused by name.
    Methods (`weak.upgrade()`, `map.get()`) are not read at all.

## What this does NOT claim

It does not say the lane sets the variable on the right invocation, only that some
non-comment line of `run-ci.sh` sets it. And it does not grade `#[ignore]`d tests'
skips: the 50 integration sites and the shared-memory `zenohd` legs, whose oracle
hosted CI does not provision at all, are the lanes' to decide. Both numbers print
every run, beside the verdict, because a green that stays quiet about what it did
not read is read as complete.

## Populations, and why each must be non-zero

A zero is exit 2, never green: no in-scope skip site means the print reader
stopped matching, no consumer means the let-else reader did.

Exit codes: 0 green, 1 a finding, 2 the gate cannot see its subject.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lib"))
import rust_comments  # noqa: E402

RUN_CI = ROOT / "scripts/run-ci.sh"
WORKFLOWS = ROOT / ".github/workflows"

PRINT_CALL = re.compile(r"\b(?:eprintln|println|eprint|print)\s*!\s*\(")
SKIP_WORD = re.compile(r"\s*\[?skip\b", re.I)
AFTER_PRINT = re.compile(r"\s*;\s*(?:return\b|None\b)")
FN_HEAD = re.compile(r"\bfn\s+(\w+)")
# `async`, `pub(crate)`, `unsafe` ... sit between the attribute run and `fn`; an
# `async fn` test read without skipping them has no attributes at all, which is
# how 15 ignored tests first read as running by default.
QUALIFIERS = re.compile(
    r'(?:\b(?:pub(?:\([^)]*\))?|async|unsafe|const|extern(?:\s+"[^"]*")?)\s+)+$')
TEST_ATTR = re.compile(r"#\[\s*(?:\w+::)*test\b[^\]]*\]")
IGNORE_ATTR = re.compile(r"#\[\s*ignore\b")
DOOR_LITERAL = re.compile(r'"([A-Z][A-Z0-9_]*_REQUIRE)"')
LET_ELSE = re.compile(
    r"\blet\s+Some\s*\([^)]*\)\s*=\s*(?P<expr>[^;{}]*?)\s+else\s*\{\s*return\b")
FREE_CALL = re.compile(r"(?<![.\w])(?:\w+::)*(\w+)\s*\(")


def tracked_rust():
    out = subprocess.run(
        # `--others` too: a helper file written this round is read before it is
        # added, and a gate that cannot see it would call its consumers silent.
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--",
         "crates"], cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("git ls-files failed: " + out.stderr.strip())
    return [ROOT / p for p in out.stdout.splitlines()
            if p.endswith(".rs") and "/target/" not in p]


def crate_of(path, root=ROOT):
    parts = Path(path).resolve().relative_to(Path(root).resolve()).parts
    return parts[1] if len(parts) > 1 and parts[0] == "crates" else parts[0]


def match_close(code, open_idx, opener, closer):
    depth = 0
    for i in range(open_idx, len(code)):
        c = code[i]
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i
    return -1


class Fn:
    def __init__(self, name, body_open, body_close, option, test, ignored):
        self.name = name
        self.body_open, self.body_close = body_open, body_close
        self.returns_option, self.is_test, self.ignored = option, test, ignored
        self.skip_sites = []
        self.doors = set()
        self.calls = set()


def fn_table(code):
    """Every fn that has a body."""
    fns = []
    for m in FN_HEAD.finditer(code):
        i, paren = m.end(), 0
        while i < len(code):
            c = code[i]
            if c == "(":
                paren += 1
            elif c == ")":
                paren -= 1
            elif paren == 0 and c in "{;":
                break
            i += 1
        if i >= len(code) or code[i] == ";":
            continue
        close = match_close(code, i, "{", "}")
        if close < 0:
            continue
        sig = code[m.end():i]
        # The attribute run directly above the fn: walk back over `#[..]` groups.
        tail = QUALIFIERS.sub("", code[max(0, m.start() - 600):m.start()]).rstrip()
        test = ignored = False
        while tail.endswith("]"):
            start = tail.rfind("#[")
            if start < 0:
                break
            group = tail[start:]
            if TEST_ATTR.fullmatch(group.strip()):
                test = True
            if IGNORE_ATTR.match(group):
                ignored = True
            tail = tail[:start].rstrip()
        fns.append(Fn(m.group(1), i, close, bool(re.search(r"->\s*Option\b", sig)),
                      test, ignored))
    return fns


def innermost(fns, idx):
    best = None
    for f in fns:
        if f.body_open < idx < f.body_close:
            if best is None or f.body_open > best.body_open:
                best = f
    return best


def skip_sites(code, lit):
    """Offsets of skip sites: a print whose first literal starts `skip`, then a bail."""
    sites = []
    for m in PRINT_CALL.finditer(code):
        open_idx = m.end() - 1
        close = match_close(code, open_idx, "(", ")")
        if close < 0:
            continue
        seg = lit[open_idx + 1:close]
        q = seg.find('"')
        if q < 0 or not SKIP_WORD.match(seg[q + 1:]):
            continue
        if AFTER_PRINT.match(code, close + 1):
            sites.append(m.start())
    return sites


class Source:
    def __init__(self, path, raw, crate):
        self.path, self.crate = path, crate
        self.lit = rust_comments.strip_comments(raw)
        self.code = rust_comments.strip_comments(raw, blank_literals=True)
        if len(self.lit) != len(self.code):
            raise RuntimeError("%s: the two comment views disagree in length, "
                               "so offsets cannot be shared" % path)
        self.fns = fn_table(self.code)
        for at in skip_sites(self.code, self.lit):
            f = innermost(self.fns, at)
            if f is not None:
                f.skip_sites.append(at)
        for f in self.fns:
            f.doors = set(DOOR_LITERAL.findall(
                self.lit[f.body_open:f.body_close]))
            f.calls = {c.group(1) for c in FREE_CALL.finditer(
                self.code[f.body_open:f.body_close])}

    def line(self, idx):
        return self.code.count("\n", 0, idx) + 1


def armed_variables(run_ci=RUN_CI, workflows=WORKFLOWS):
    """Variables a lane or a job sets: `run-ci.sh` assignments on non-comment
    lines, and `NAME:` entries of a workflow's `env:` mapping.

    Both are real arming sites in this repository: a lane arms what it built
    itself (`local -x`), and a job arms what it provisioned (`WZ_Z_REQUIRE`).
    """
    text = Path(run_ci).read_text().replace("\\\n", " ")
    armed = set()
    for line in text.split("\n"):
        if line.lstrip().startswith("#"):
            continue
        for m in re.finditer(r"(?<![\w$])([A-Z][A-Z0-9_]*_REQUIRE)=", line):
            armed.add(m.group(1))
    for path in sorted(Path(workflows).glob("*.yml")):
        for line in path.read_text().split("\n"):
            m = re.match(r"\s*([A-Z][A-Z0-9_]*_REQUIRE)\s*:\s*\S", line)
            if m:
                armed.add(m.group(1))
    return armed


def reachable(roots, by_name, crate):
    seen, todo = {}, list(roots)
    while todo:
        f = todo.pop()
        if id(f) in seen:
            continue
        seen[id(f)] = f
        for name in f.calls:
            todo.extend(by_name.get((crate, name), ()))
    return seen


def grade(sources, armed):
    """Returns (findings, populations)."""
    findings = []
    by_name = {}
    for s in sources:
        for f in s.fns:
            by_name.setdefault((s.crate, f.name), []).append(f)

    # What the tests that run by default reach, and what only the ignored ones do.
    default_reach, ignored_reach = {}, {}
    for s in sources:
        by_default = [f for f in s.fns if f.is_test and not f.ignored]
        by_lane = [f for f in s.fns if f.is_test and f.ignored]
        default_reach.update(reachable(by_default, by_name, s.crate))
        ignored_reach.update(reachable(by_lane, by_name, s.crate))

    sites = lane_owned = 0
    doors_read = set()
    for s in sources:
        for f in s.fns:
            for at in f.skip_sites:
                if id(f) not in default_reach and id(f) in ignored_reach:
                    lane_owned += 1
                    continue
                sites += 1
                doors = set()
                for g in reachable([f], by_name, s.crate).values():
                    doors |= g.doors
                if not doors:
                    findings.append(
                        "%s:%d  `%s` prints a skip and bails out in a test that "
                        "runs by default, and neither it nor anything it calls "
                        "names a `\"<WORD>_REQUIRE\"` variable -- no lane can "
                        "make the absent fixture a failure"
                        % (s.path, s.line(at), f.name))
                doors_read |= doors
    for var in sorted(doors_read - armed):
        findings.append(
            "`%s` is a door no lane arms: scripts/run-ci.sh sets it on no "
            "non-comment line, so the skip it guards stays a skip" % var)

    consumers = silent = 0
    for s in sources:
        for f in s.fns:
            if not f.is_test or f.ignored:
                continue
            body = s.code[f.body_open:f.body_close]
            for m in LET_ELSE.finditer(body):
                for c in FREE_CALL.finditer(m.group("expr")):
                    cands = [h for h in by_name.get((s.crate, c.group(1)), ())
                             if h.returns_option]
                    if not cands:
                        continue
                    consumers += 1
                    # The note may be one call down: a helper that only forwards
                    # to the shared door says it through the door.
                    if not any(g.skip_sites
                               for h in cands
                               for g in reachable([h], by_name, s.crate).values()):
                        silent += 1
                        findings.append(
                            "%s:%d  test `%s` bails out when `%s(..)` yields "
                            "`None`, and that helper says nothing: a pass here "
                            "is indistinguishable from a test that ran"
                            % (s.path, s.line(f.body_open + m.start()),
                               f.name, c.group(1)))
    return findings, {"skip_sites": sites, "lane_owned": lane_owned,
                      "doors": len(doors_read), "consumers": consumers,
                      "silent_consumers": silent}


def report(findings, pop):
    print("  silent-skip: %d skip site(s) in tests that run by default, %d "
          "door variable(s) read; %d test(s) bail out on an Option helper, %d "
          "of them on a silent one"
          % (pop["skip_sites"], pop["doors"], pop["consumers"],
             pop["silent_consumers"]))
    print("  silent-skip: %d further skip site(s) are reached only by #[ignore]d "
          "tests and are NOT graded here -- the lane's preflight owns them "
          "(armed_skip_guard.py)" % pop["lane_owned"])
    if pop["skip_sites"] == 0 or pop["consumers"] == 0:
        print("  FAIL silent-skip: a population is EMPTY (skip sites %d, "
              "consumers %d) -- the reader stopped matching, which a green "
              "would hide" % (pop["skip_sites"], pop["consumers"]),
              file=sys.stderr)
        return 2
    for f in findings:
        print("  FAIL " + f, file=sys.stderr)
    if findings:
        return 1
    print("  silent-skip: OK -- every default-run skip can be made a failure by "
          "an armed lane, and no such test skips on a helper that stays quiet")
    return 0


def load(paths):
    return [Source(str(p), p.read_text(), crate_of(p)) for p in paths]


FIXTURE_GOOD = '''
fn built() -> Option<u32> {
    let required = std::env::var("WZ_FIXTURE_REQUIRE").is_ok();
    if required { panic!("absent"); }
    eprintln!("skip: not built");
    None
}
#[test]
fn consumer() {
    let Some(x) = built() else { return; };
    assert_eq!(x, 1);
}
#[test]
fn weak_is_not_a_fixture() {
    let Some(s) = weak.upgrade() else { return; };
}
// eprintln!("skip: in a comment"); return;
'''
FIXTURE_NO_DOOR = '''
#[test]
fn inline() {
    if !p.exists() {
        eprintln!("skip: not built");
        return;
    }
}
'''
FIXTURE_SILENT = '''
fn quiet() -> Option<u32> { None }
#[test]
fn consumer() {
    let Some(x) = quiet() else { return; };
}
'''
FIXTURE_LANE_OWNED = '''
fn oracle() -> Option<u32> {
    eprintln!("skip: oracle absent");
    None
}
#[tokio::test(flavor = "multi_thread")]
#[ignore = "binary-dep e2e; Layer X runs via --ignored"]
pub(crate) async fn ignored_consumer() {
    let Some(x) = oracle() else { return; };
}
'''


def selftest():
    armed = {"WZ_FIXTURE_REQUIRE"}

    def run(text, armed=armed, crate="c"):
        return grade([Source("fx.rs", text, crate)], armed)

    ok = True

    def expect(label, cond):
        nonlocal ok
        print("  selftest %-60s %s" % (label, "ok" if cond else "FAIL"))
        ok = ok and cond

    findings, pop = run(FIXTURE_GOOD)
    expect("a door-bearing helper and its consumer are clean", not findings)
    expect("the skip site and its door variable are counted",
           pop["skip_sites"] == 1 and pop["doors"] == 1)
    expect("the consumer is read, the method call and comment are not",
           pop["consumers"] == 1)
    findings, pop = run(FIXTURE_GOOD, armed=set())
    expect("a door no lane arms is a finding",
           len(findings) == 1 and "no lane arms" in findings[0])
    findings, pop = run(FIXTURE_NO_DOOR)
    expect("an inline default-run skip with no door is a finding",
           len(findings) == 1 and "REQUIRE" in findings[0])
    findings, pop = run(FIXTURE_SILENT)
    expect("a quiet Option helper behind a let-else is a finding",
           len(findings) == 1 and "says nothing" in findings[0])
    findings, pop = run(FIXTURE_LANE_OWNED)
    expect("a skip reached only by an ignored test is lane-owned, not graded",
           not findings and pop["lane_owned"] == 1 and pop["skip_sites"] == 0)
    code = rust_comments.strip_comments(FIXTURE_GOOD, True)
    lit = rust_comments.strip_comments(FIXTURE_GOOD)
    expect("both comment views keep identical offsets", len(code) == len(lit))
    rc = report([], {"skip_sites": 0, "lane_owned": 0, "doors": 0,
                     "consumers": 0, "silent_consumers": 0})
    expect("an empty population is exit 2, not green", rc == 2)
    return 0 if ok else 1


def main(argv):
    if len(argv) != 2 or argv[1] not in ("--check", "--selftest"):
        print("usage: silent_skip_gate.py --check | --selftest",
              file=sys.stderr)
        return 2
    if argv[1] == "--selftest":
        return selftest()
    findings, pop = grade(load(tracked_rust()), armed_variables())
    return report(findings, pop)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
