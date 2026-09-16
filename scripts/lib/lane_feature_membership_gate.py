#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
r"""R2659 (no register item) — an e2e test must not run against a binary that
lacks a feature its own `#[ignore]` note declares.

The citation is `no register item` for the reason `round_fed_gate_reach.py`
gives for its own: the defect this closes is item 762 of the operator's
agent-memory register, which has no store `debt-` id for
`gate_provenance_lint` to resolve. Naming it in prose here and `no register
item` in the citation is the honest pair.

## What generated the defect this closes

R2655 added `wz_router_hat_config_key_delete_restores_the_default_over_the_wire`
to `wz_router_hat_connect_reconcile.rs`. Layer E7b selected it — its filter was
a DENY-list of three name fragments and the new name matched none of them — and
ran it against a `wz-ap-demo` built without `router-config-mutate`. The host
decoded the write and applied nothing, and the test failed on its own setup
assert. Three hosted runs died there, and because the layer is fail-fast, Layer
E7b2 — the lane that owns the test — never ran on any of them.

## Why this grades FEATURES and not the lane NAME

Every `#[ignore]` note already names its lane ("Layer E7b2 runs via
--ignored"), so the obvious gate is "the lane that selects it must be the lane
its note names". That gate is REFUTED, measured over this tree:

  * 111 of 486 notes disagree with the lanes today, and the only available
    source for repairing them is the lanes the gate would then check. A note
    transcribed from the lane can never disagree with it — the
    `a_gate_can_inherit_the_weakness_it_escaped` shape.
  * 52 of those disagreements are LEGITIMATE: 19 tests are deliberately run by
    both `layer_e_ap_demo_round_trip` and `layer_epico_library_oracles`, 17 by
    both `layer_c1cc_api_compat_c` and `layer_c1cd_api_compat_c_attachment`. A
    name gate needs an exemption vocabulary for them; a feature gate does not
    care, because both lanes build binaries that satisfy the requirement.
  * And the name is not what broke. R2655 did not fail because a label said
    E7b2. It failed because E7b's BINARY lacked `router-config-mutate`.

The note's feature list is a REQUIREMENT, authored independently of CI; the
lane's `cargo build --features` is a FACT about the binary. Neither can be made
to agree with the other by copying, which is what makes the comparison worth
running.

## The rule

    for each ignored test T, for each lane L whose --ignored invocation selects T:
        N = features T's note declares for binary B
        C = feature_closure.closure(B, L's build features for B)
        for f in N - C:
            FAIL if f has >= 1 own `cfg(feature = "f")` site under crates/

⭐ THE 0-CFG-SITE FILTER IS LOAD-BEARING AND MEASURED, not a softener.
`session-extqos` is absent from Layer Z's closure and four tests declare it —
but it carries zero own cfg sites (the code is gated by `transport-qos`, which
IS in that closure), so its absence cannot change that binary. Without this
filter the gate reports 34 violations and several are noise. A feature that no
`cfg` mentions by name cannot elide anything by name.

## Verified as a DISCRIMINATOR, not asserted

Run against the defect it was derived from (`cargo tree` resolving both):

    E7b  (the lane that wrongly ran it) — closure 97 features
       absent: adminspace-router-linkstate  19 own cfg sites -> REFUTES
       absent: adminspace-write              5 own cfg sites -> REFUTES
       absent: router-config-mutate          8 own cfg sites -> REFUTES
    E7b2 (the lane that owns it)      — closure 101 features
       => SILENT

It fails on the defect, passes on the correct configuration, and names the
feature whose absence caused the failure.

## What it refuses rather than skips

An `--ignored` invocation whose shape this cannot express is a FAILURE, never a
silent skip — `reference_lesson_a_gate_name_can_be_unrepresentable`. TEN shapes
exist in `run-ci.sh` today and seven of them produced a WRONG VERDICT here
before they were handled: a filter before `--`, a filter after `--` (libtest's),
`--exact`, `--skip` deny-lists, `--lib <filter>`, several `--test` flags in one
invocation, `for VAR in <names>` loops, SEVERAL such loops per lane all naming
the variable `leg`, `2>&1`/`| tee | grep` tails, and a lane REBUILDING a binary
mid-lane so ordering decides which build a test sees.

⛔ It also does NOT reuse `feature_closure.ap_demo_lane_features()`, which
unions every lane's features — deliberately a superset for Layer A4's
refutation direction, and a superset makes every test here pass. Nor does it
reuse that function's scraper regex, which `run-ci.sh` itself warns "cannot
cross a newline"; this joins `\`-continuations before scanning.

## What a green here does NOT cover

The feature arm reaches only the tests whose note declares a `<package>
--features`; the rest are checked for lane membership ALONE. Both numbers print
every run, beside the verdict, because the OK line otherwise reads as a claim
about the whole corpus.
"""
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# ⚠ TOP-LEVEL, not inside `check()`. `round_fed_gate_reach.py` builds its
# population as the transitive closure of its seeds under "imports a sibling
# module", read from the AST — and a function-local import is a weaker thing to
# read. This module is its own seed twice over (it names `scripts/run-ci.sh` and
# globs under `crates/`), but the import should still say what it is.
sys.path.insert(0, str(ROOT / "scripts/lib"))
import feature_closure  # noqa: E402

TESTS_DIR = ROOT / "crates/wz-integration-tests/tests"
RUN_CI = ROOT / "scripts/run-ci.sh"
CRATES = ROOT / "crates"

# ── side A: the tests ────────────────────────────────────────────────
#
# ⚠ Read as TEXT, not line by line: 84 of this tree's 486 ignore notes span
# more than one line, and 69 of the tests are `async fn`.
IGNORE_ATTR = re.compile(r'#\[ignore\s*=\s*"((?:[^"\\]|\\.)*)"\]', re.S)
FN_AFTER = re.compile(
    r'(?:#\[[^\]]*\]\s*|\s)*(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z0-9_]+)',
    re.S)
# `--features a,b,c` inside the note, attributed to the NEAREST PRECEDING real
# package name.
#
# ⛔ NOT "the word immediately before `--features`". A note writes the binary in
# prose as often as adjacent to the flag — `"needs target/zenohd/zenohd and a
# wz-ap-demo built with --features zenoh-config"` — and an adjacency rule reads
# the English word `with` as the binary. That is not merely noise: the REAL
# requirement then belongs to a binary no lane builds, so it is dropped from the
# graded population and reported as a deferral. A gate that silently narrows its
# own population is the class this gate exists to catch, so it may not do it.
NOTE_FEATURES = re.compile(r'--features\s+([A-Za-z0-9_,\-]+)')
NOTE_TOKEN = re.compile(r'[a-z][a-z0-9_-]*')


def _strip_line_comments(text, marker):
    """Blank every line whose first non-space characters are `marker`.

    ⚠ Both inputs discuss themselves in prose. 78 `#[ignore` occurrences in the
    test corpus sit inside `///` comments, and `run-ci.sh` carries a comment
    reading "`cargo test -- --ignored` that selects nothing still ..." — read as
    code, that one invocation appears to claim every ignored test in the tree.
    """
    out = []
    for line in text.split("\n"):
        out.append("" if line.lstrip().startswith(marker) else line)
    return "\n".join(out)


def note_requirements(note, packages):
    """{binary: {features}} from one note, plus the `--features` runs it could
    not attribute to any real package."""
    requires, orphaned = {}, []
    for m in NOTE_FEATURES.finditer(note):
        binary = None
        for t in NOTE_TOKEN.finditer(note[:m.start()]):
            if t.group(0) in packages:
                binary = t.group(0)          # keep the LAST one before the flag
        if binary is None:
            orphaned.append(m.group(1))
            continue
        requires.setdefault(binary, set()).update(m.group(1).split(","))
    return requires, orphaned


def workspace_packages(crates=CRATES):
    """dir -> package name, reusing `guarded_count_gate`'s reader.

    ⛔ Not a second parser, and not `tomllib`: the python floor is (3, 10) and
    `python_floor_lint` bans it by name.
    """
    sys.path.insert(0, str(ROOT / "scripts/lib"))
    import guarded_count_gate
    return guarded_count_gate.package_manifest_names(Path(crates))


def ignored_tests(tests_dir=TESTS_DIR, packages=None):
    if packages is None:
        packages = set(workspace_packages().values())
    rows = []
    for path in sorted(Path(tests_dir).glob("*.rs")):
        text = _strip_line_comments(path.read_text(), "//")
        for m in IGNORE_ATTR.finditer(text):
            note = m.group(1)
            fm = FN_AFTER.match(text[m.end():])
            if not fm:
                continue
            requires, orphaned = note_requirements(note, packages)
            rows.append({
                "target": path.stem,
                "fn": fm.group(1),
                "requires": requires,
                "orphaned": orphaned,
            })
    return rows


# ── side B: the lanes ────────────────────────────────────────────────
LAYER_FN = re.compile(r'^(layer_[a-z0-9_]+)\(\)\s*\{', re.M)
CARGO_TEST = re.compile(r'cargo test\b[^\n]*')
CARGO_BUILD = re.compile(r'cargo build\b[^\n]*')


class Unexpressable(Exception):
    """An invocation this gate cannot simulate. Never swallowed."""


FOR_LOOP = re.compile(r'\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^;]*?);\s*do\b')


def loop_vars(body):
    """`for leg in a b c; do` -> [(offset, "leg", ["a", "b", "c"])].

    ⛔ THIS IS THE TREE'S IDIOM, NOT AN ODDITY, and reading it is the gate's job.
    An earlier draft refused every runtime-assembled filter as unexpressable and
    concluded that R2658 had introduced the shape. Measured: 14 invocations
    across 10 lanes drive per-leg loops this way — `layer_c1cc_api_compat_c`,
    `layer_e12_apfull_adminspace_pico`, `layer_e13/e14/e15`, `layer_c1bp`,
    `layer_e8t` and others — because each leg needs its own prereq check and its
    own `1 passed` assertion. The names are LITERAL and one per line in every
    one of them, so a gate that cannot resolve them is refusing to read
    something plainly written, and would have demanded ten lanes be rewritten
    around its own limitation.

    ⛔ SCOPED BY POSITION, NOT BY NAME. A lane commonly runs SEVERAL such loops
    in sequence, one per test file, and they all call the variable `leg` —
    `layer_c1cc_api_compat_c` has four. A dict keyed by the variable name keeps
    only the last, so every test named by an earlier loop reads as selected by
    nothing: that mistake reported 19 live tests as running nowhere.
    """
    out = []
    for m in FOR_LOOP.finditer(body):
        names = [n for n in m.group(2).split() if n and not n.startswith("-")]
        if names:
            out.append((m.start(), m.group(1), names))
    return out


def resolve_loop_var(loops, var, at):
    """The names `var` takes for an invocation at offset `at` — the nearest
    enclosing `for` block, which is the last one declaring `var` before it."""
    best = None
    for start, name, names in loops:
        if name == var and start < at:
            best = names
    return best


def parse_invocation(cmd, loops=None, at=0):
    """(package, kind, [targets], filter, [skips], exact) for one cargo line.

    Raises Unexpressable for a filter this cannot resolve statically — a shell
    variable no `for` block names, a glob, a command substitution.
    """
    # ⛔ TRUNCATE AT THE FIRST SHELL OPERATOR. The invocation is lifted out of a
    # subshell that often continues `2>&1 | tee /dev/stderr | grep -qE '...'`,
    # and every word of that pipeline is a bare word — which a naive reader
    # takes for a test-name filter.
    raw = []
    for t in cmd.split():
        if t in ("|", "||", "&&", ";") or t.startswith("|"):
            break
        # A REDIRECTION ENDS THE COMMAND TOO. `2>&1` is a bare word, and once a
        # filter is accepted on either side of `--` a reader takes it for one —
        # then the invocation selects nothing and every test in the file reads
        # as running nowhere. Layer Z writes `-- --ignored --quiet
        # --test-threads=1 2>&1 | tee ...` on 30-odd legs.
        if re.match(r'^\d*(>>?|<|&>)', t):
            break
        clean = t.strip("\"'")
        stop = False
        # `"$leg");` is the last token of a loop body: the filter, the subshell
        # close and the separator in one word. Take the filter, then stop.
        if ")" in clean or ";" in clean:
            clean = clean.split(")")[0].split(";")[0]
            stop = True
        if clean:
            raw.append(clean)
        if stop:
            break
    toks = raw
    package = None
    kind = "all"
    targets = []
    positive = None
    skips = []
    exact = "--exact" in toks
    i = 2  # past `cargo test` / `cargo build`; both are bare words
    while i < len(toks):
        t = toks[i]
        if t in ("-p", "--package"):
            package = toks[i + 1] if i + 1 < len(toks) else None
            i += 2
        elif t == "--test":
            kind = "test"
            if i + 1 < len(toks):
                targets.append(toks[i + 1])   # ⚠ repeatable: Layer E2 passes six
            i += 2
        elif t in ("--lib", "--bins", "--doc", "--benches", "--examples"):
            kind = t.lstrip("-")
            i += 1
        elif t == "--bin":
            kind = "bin"
            i += 2
        elif t == "--skip":
            skips.append(toks[i + 1].strip('"\''))
            i += 2
        elif t == "--":
            i += 1
        elif t.startswith("-"):
            i += 2 if t in ("--features", "--manifest-path", "--target", "--profile") else 1
        else:
            # ⚠ A FILTER MAY SIT ON EITHER SIDE OF `--`. Layer E8t writes
            # `-- --ignored --exact <name>`, handing the name to libtest rather
            # than to cargo; both work, and a reader that only looks before `--`
            # sees no filter at all and concludes the invocation selects the
            # WHOLE file. That mistake put six of Layer E8t's positive tests on
            # its feature-off binary in this gate's own first report.
            if positive is None:
                positive = t.strip('"\'')
                if any(c in positive for c in "$`*?"):
                    var = positive.lstrip("$").strip("{}")
                    names = resolve_loop_var(loops or [], var, at)
                    if not names:
                        raise Unexpressable(
                            "filter %r is assembled at runtime and no `for %s in "
                            "...` in this lane names its values; this gate cannot "
                            "say which tests it selects" % (positive, var))
                    positive = names
            i += 1
    return package, kind, targets, positive, skips, exact


def lane_table(run_ci=RUN_CI):
    """Each lane as an ORDERED event list, and the order is load-bearing.

    ⛔ A LANE MAY BUILD THE SAME BINARY MORE THAN ONCE. Layer E8t builds
    `wz-ap-demo --features router-hat-router,time-hlc`, runs its positive tests,
    then REBUILDS `--features router-hat-router` over the same path for the
    feature-off negative — and E7b says so in its own words: "the ORDERING, not
    any non-clobber property, is what keeps each test on the binary it needs".
    A table that keeps one build per package therefore grades the positive tests
    against the negative binary. It did: the first run of this gate reported six
    `time-hlc` violations that are not violations at all.

    So each `cargo test` is paired with the build state AT ITS OWN POSITION.
    """
    text = _strip_line_comments(Path(run_ci).read_text(), "#").replace("\\\n", " ")
    starts = [(m.start(), m.group(1)) for m in LAYER_FN.finditer(text)]
    starts.append((len(text), None))
    lanes = {}
    for i in range(len(starts) - 1):
        begin, name = starts[i]
        body = text[begin:starts[i + 1][0]]
        events = []
        for m in CARGO_BUILD.finditer(body):
            cmd = " ".join(m.group(0).split())
            toks = [t.rstrip(")") for t in cmd.split()]
            pkg, feats = None, ()
            for j, t in enumerate(toks):
                if t in ("-p", "--package") and j + 1 < len(toks):
                    pkg = toks[j + 1]
                elif t == "--features" and j + 1 < len(toks):
                    feats = tuple(sorted(toks[j + 1].strip('"\'').split(",")))
            if pkg:
                events.append((m.start(), "build", (pkg, feats)))
        for m in CARGO_TEST.finditer(body):
            cmd = " ".join(m.group(0).split())
            if "--ignored" in cmd:
                events.append((m.start(), "test", cmd))
        if events:
            lanes[name] = (sorted(events), loop_vars(body))
    return lanes


def lane_runs(events):
    """(offset, invocation, {pkg: features}) per --ignored test, in lane order."""
    state, out = {}, []
    for at, kind, payload in events:
        if kind == "build":
            pkg, feats = payload
            state[pkg] = feats
        else:
            out.append((at, payload, dict(state)))
    return out


def selects(name, positive, skips, exact):
    """`positive` is None, one filter, or the list a `for` loop iterates."""
    if positive is not None:
        candidates = positive if isinstance(positive, list) else [positive]
        if exact:
            if name not in candidates:
                return False
        elif not any(c in name for c in candidates):
            return False
    return not any(s in name for s in skips)


# ── the cfg-site filter ──────────────────────────────────────────────
CFG_FEATURE = re.compile(r'feature\s*=\s*"([^"]+)"')


def cfg_site_counts(crates=CRATES):
    """How many `cfg(feature = "X")` sites the tree carries, per feature.

    One walk, not one grep per feature: the question is asked for every absent
    feature of every (test, lane) pair.
    """
    counts = Counter()
    for path in Path(crates).rglob("*.rs"):
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        if "feature" not in text:
            continue
        counts.update(CFG_FEATURE.findall(text))
    return counts


def check(tests_dir=TESTS_DIR, run_ci=RUN_CI, crates=CRATES, resolver=None,
          packages=None):
    if resolver is None:
        resolver = feature_closure.closure
    if packages is None:
        packages = set(workspace_packages().values())

    rows = ignored_tests(tests_dir, packages)
    lanes = lane_table(run_ci)
    sites = cfg_site_counts(crates)

    unexpressable, violations = [], []
    unclaimed, ungradable, graded = [], 0, 0

    parsed = []
    for lane, (events, loops) in lanes.items():
        for at, cmd, builds in lane_runs(events):
            try:
                parsed.append((lane, parse_invocation(cmd, loops, at), builds))
            except Unexpressable as e:
                unexpressable.append((lane, cmd, str(e)))

    for row in rows:
        # A note that declares `--features` but names no package this workspace
        # has is a requirement nobody can grade. Saying so is the point.
        for feats in row.get("orphaned", []):
            unexpressable.append((
                "%s::%s" % (row["target"], row["fn"]),
                "--features %s" % feats,
                "the note declares features but names no workspace package "
                "before the flag, so this gate cannot say which binary must "
                "carry them",
            ))
        claimed = []
        for lane, inv, builds in parsed:
            package, kind, targets, positive, skips, exact = inv
            if kind not in ("test", "all"):
                continue
            if package not in (None, "wz-integration-tests"):
                continue
            if targets and row["target"] not in targets:
                continue
            if selects(row["fn"], positive, skips, exact):
                claimed.append((lane, builds))
        if not claimed:
            unclaimed.append(row)
            continue
        for lane, builds in claimed:
            for binary, needed in row["requires"].items():
                if binary not in builds:
                    ungradable += 1
                    continue
                graded += 1
                absent = needed - set(resolver(binary, builds[binary]))
                for f in sorted(absent):
                    if sites.get(f, 0):
                        violations.append((row, lane, binary, f, sites[f]))
    return {
        "tests": rows, "lanes": lanes, "graded": graded,
        # Lanes whose `--ignored` invocation can reach an INTEGRATION test —
        # not merely lanes that pass `--ignored`. One lane runs `--ignored`
        # against `--lib`, which selects none of these 486, and counting it
        # would make the denominator mean something the sentence does not say.
        "selecting_lanes": len({
            lane for lane, (pkg, kind, _t, _p, _s, _e), _b in parsed
            if kind in ("test", "all")
            and pkg in (None, "wz-integration-tests")
        }),
        "ungradable": ungradable, "unclaimed": unclaimed,
        "unexpressable": unexpressable, "violations": violations,
    }


def report(res):
    # ⚠ THE DENOMINATOR IS THE LANES THAT CAN SELECT, not every lane that runs
    # cargo. Measured at R2659: 71 lanes carry a build or a test, but only 42
    # issue an `--ignored` invocation that can reach an integration test, so
    # "over 71 lanes" overstated the selecting population by 69%. A summary line
    # is what a reader judges coverage by, so it says the number it means.
    print("  lane-feature-membership: %d ignored e2e test(s) over %d lane(s) "
          "that can select one (%d run cargo at all); %d (test, lane, binary) "
          "triple(s) graded"
          % (len(res["tests"]), res["selecting_lanes"], len(res["lanes"]),
             res["graded"]))
    # ⛔⛔ THE COVERAGE PRINTS EVERY RUN, beside the verdict, because without it
    # the OK line reads as a claim about all 486 tests and is only a claim about
    # the ones that declare a binary. Measured at R2659: 163 declare one (every
    # one of them `wz-ap-demo`), 323 declare none — so the feature arm is silent
    # for two thirds of the population and those tests are checked ONLY for
    # "some lane selects me". A gate that reports what it measured and stays
    # quiet about what it could not is read as complete; this one says so.
    declaring = sum(1 for r in res["tests"] if r["requires"])
    print("  lane-feature-membership: the FEATURE arm reaches %d of %d test(s) "
          "— the rest declare no `<package> --features` in their note and are "
          "graded by lane membership ALONE, which a green here does not cover"
          % (declaring, len(res["tests"])))
    print("  lane-feature-membership: %d triple(s) UNGRADED — the note names a "
          "binary the lane does not build (it inherits whatever a prior lane "
          "left in target/); not a pass" % res["ungradable"])
    bad = False
    for lane, cmd, why in res["unexpressable"]:
        bad = True
        print("  FAIL %s: %s\n       %s" % (lane, why, cmd[:120]))
    for row in res["unclaimed"]:
        bad = True
        print("  FAIL %s::%s is selected by NO --ignored invocation — it runs "
              "nowhere" % (row["target"], row["fn"]))
    for row, lane, binary, f, n in res["violations"]:
        bad = True
        print("  FAIL %s::%s runs in %s, whose %s closure lacks `%s` "
              "(%d cfg site(s) elide with it)"
              % (row["target"], row["fn"], lane, binary, f, n))
    if not bad:
        print("  lane-feature-membership: OK — every ignored test runs against "
              "a binary carrying every feature its own note declares")
    return 1 if bad else 0


def selftest():
    """Drive the whole pipeline over a fixture carrying the shapes that bit."""
    import tempfile
    shapes = []
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        t = d / "tests"
        t.mkdir()
        (t / "alpha.rs").write_text(
            '/// prose mentioning #[ignore = "Layer X"] must not count\n'
            '#[ignore = "binary-dep e2e (demo --features needed,harmless,inert);\n'
            '            Layer A runs via --ignored"]\n'
            '#[tokio::test]\n'
            'async fn alpha_needs_a_feature() {}\n'
            '#[ignore = "binary-dep e2e (demo --features harmless); Layer A"]\n'
            'fn alpha_is_fine() {}\n')
        (t / "beta.rs").write_text(
            '#[ignore = "binary-dep e2e (demo --features harmless); Layer B"]\n'
            'fn beta_runs_nowhere() {}\n')
        ci = d / "run-ci.sh"
        ci.write_text(
            "# a comment: cargo test -p wz-integration-tests -- --ignored\n"
            "layer_a() {\n"
            "    (cd crates && cargo build -p demo --features harmless --quiet)\n"
            "    (cd crates && cargo test -p wz-integration-tests \\\n"
            "        --test alpha --quiet -- --ignored)\n"
            "}\n"
            "layer_c() {\n"
            "    (cd crates && cargo build -p demo --features harmless)\n"
            "    (cd crates && cargo test -p wz-integration-tests --test alpha "
            "alpha_is_fine -- --ignored --exact)\n"
            "}\n"
            "layer_d() {\n"
            "    (cd crates && cargo build -p demo --features harmless)\n"
            '    for leg in alpha_is_fine; do (cd crates && cargo test '
            '-p wz-integration-tests --test alpha -- --ignored --exact "$leg"); done\n'
            "}\n"
            "layer_e() {\n"
            '    (cd crates && cargo test -p wz-integration-tests --test beta '
            '"$undeclared" -- --ignored)\n'
            "}\n")
        crates = d / "crates"
        crates.mkdir()
        (crates / "lib.rs").write_text(
            '#[cfg(feature = "needed")] fn gated() {}\n')

        res = check(tests_dir=t, run_ci=ci, crates=crates,
                    resolver=lambda pkg, feats: frozenset(feats),
                    packages={"demo"})

        shapes.append(("a note in prose is not an attribute",
                       len(res["tests"]) == 3))
        shapes.append(("a multi-line note is read",
                       any(r["fn"] == "alpha_needs_a_feature" for r in res["tests"])))
        # ⚠ A PAIR, and the first arm is what stops the second from being a
        # blanket refusal. A gate that cannot read `for leg in <names>` would
        # call ten of this tree's lanes unexpressable and demand they be
        # rewritten around its own limitation.
        shapes.append(("a `for VAR in <names>` filter is RESOLVED, not refused",
                       not any("leg" in why for _, _, why in res["unexpressable"])))
        shapes.append(("a variable no loop declares is refused, not skipped",
                       len(res["unexpressable"]) == 1
                       and "undeclared" in res["unexpressable"][0][2]))
        shapes.append(("a test no lane selects is a failure",
                       [r["fn"] for r in res["unclaimed"]] == ["beta_runs_nowhere"]))
        # ⚠ THESE TWO ARE A PAIR AND NEITHER IS VALID ALONE. `needed` and
        # `inert` are BOTH declared by the note and BOTH absent from the build;
        # the only difference is that one has a cfg site in the fixture crate
        # and the other has none. A first draft asserted the negative arm
        # against a feature the fixture never mentioned, so `all(...)` held over
        # an empty population and the arm proved nothing.
        shapes.append(("an absent feature WITH a cfg site fails",
                       any(v[3] == "needed" for v in res["violations"])))
        shapes.append(("an absent feature with NO cfg site is silent",
                       all(v[3] != "inert" for v in res["violations"])))
        shapes.append(("a comment is not an invocation",
                       "layer_a" in res["lanes"] and len(res["lanes"]) == 4))
    ok = True
    for name, passed in shapes:
        print("  %s %s" % ("ok  " if passed else "FAIL", name))
        ok = ok and passed
    print("  lane-feature-membership selftest: %s (%d arm(s))"
          % ("OK" if ok else "FAILED", len(shapes)))
    return 0 if ok else 1


def main(argv):
    if "--selftest" in argv:
        return selftest()
    return report(check())


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
