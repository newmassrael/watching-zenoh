#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2213 (no register item) — WHAT A GATE WRITES IN BACKTICKS INSIDE ITS OWN
TABLES MUST EXIST, ACROSS EVERY GATE AND NOT JUST THE ONE THAT CHECKS ITSELF.

Answers item 566 of the unregistered register, which lives outside this
repository -- the reason the citation reads "no register item", the position
`debt_plane_census.py` and `armed_oracle_census.py` already record for
themselves.

## The gap, measured rather than asserted

R2212 widened `analysis_surface_parity.py` so that every backticked token in
every one of ITS four reason tables resolves against the tree, and left behind
the number that made the class visible: fifteen scripts under `scripts/lib`
carry backticked tokens inside module-level UPPERCASE tables, 182 of them, and
exactly ONE of those scripts checked its own. The other fourteen assert things
nothing has ever looked at.

That is the shape this repository keeps paying for from the other side. A
citation that rots does not go red; it keeps reading like a fact. CLAUDE.md
carries its rule against machine-local paths because one sat there for months
pointing at a directory that had ceased to exist, quoted rather than checked
the whole time.

## THREE CLASSES, and the default is the strict one

Not every backtick is a citation, and item 566 named that as the hard part. It
is genuinely hard, and it is derivable -- MEASURED this round, in the order the
derivations must run:

  REGEX    The table IS a regular expression: it is built by an `re` call, or
           it reaches an `re` function AS THE PATTERN ARGUMENT. Its backtick is
           grammar being matched, not a name being cited. A TOKEN-SHAPE test,
           and it runs FIRST -- `dissect_name_census.py`'s `REASON_BACKTICK` is
           a pattern that is read only from inside the selftest closure, so the
           reader test below would have called it a fixture. Who reads a regex
           says nothing about whether its backtick is a claim.

  FIXTURE  Every function that reaches the table is inside the selftest's own
           call closure. Derived twice over: the closure is seeded from the `if
           ... selftest` BRANCH and walked through the call graph, never from a
           function's name, and the readers are followed THROUGH module-level
           composition -- `unhonoured_kind_evidence_gate.py`'s `_FIXTURE_SRC`
           is assembled into `_FIXTURE_FILES` at module level, so a direct-only
           reader test reports `<module>` and reads like a counterexample. It
           is not one; it is a chain.

  REASON   Everything else, and it is the DEFAULT on purpose. A table this file
           cannot classify is one whose claims must resolve, so an unrecognised
           shape lands on the strict side rather than slipping through. Rule:
           unclassified is red, never a pass.

MEASURED over the tree the round it was written: 163 REASON, 15 FIXTURE, 4
REGEX. Eleven of the fifteen scripts have no selftest at all, so their FIXTURE
class is empty by construction rather than by judgement, and this file says so
rather than letting a zero read as a verdict.

## How a REASON token resolves, and where it may NOT look

Five arms, typed by the token's own shape, and the corpus is the half that
matters most:

  * a SIBLING ROW KEY -- a token naming a key of some table in the same module,
    which is a claim about that module and true by inspection;
  * a TRACKED PATH -- slash-bearing, whitespace-free, first segment a directory
    git tracks; resolved against `git ls-files`, globs included;
  * an INVENTORY-ID GLOB -- see below;
  * an IDENTIFIER -- resolved in COMMENT-STRIPPED `crates/**` source;
  * a PHRASE (it has a space) -- resolved in the whole text, comments included,
    because a sentence is a claim about what the documentation SAYS.

## The INVENTORY-ID GLOB arm (R2214), and why its shape is narrow

`apfull_membership.py` cites `platform-*`, `runtime-*` and `api-compat-*`. Those
are neither source identifiers nor files: they are GLOBS OVER THE STORE'S
INVENTORY IDS, and the claim is that the inventory holds members under those
prefixes. MEASURED: seven, six and two respectively.

The shape test is deliberately narrow -- lowercase, digits, hyphen and glob
characters only, with at least one glob character and no whitespace. A wider
"has a glob char and no slash" test was written first and MEASURED to catch
seven tokens where only three are inventory globs: `#[must_use] Discarded` and
`*lost +=` carry `[` and `*`, and `((?:z|ze|zc|zp)_[A-Za-z0-9_]*\\*?)` is a
regular expression. Those three must keep falling through to the arms that own
them.

⚠ MEASURED rather than asserted, because the obvious claim is too strong: with
the loose shape restored, the live budget does NOT move. Two of the three carry
whitespace and are refused either way, and the regular expression, read as an
`fnmatch` pattern, happens to match no inventory id -- so today the narrowness
buys nothing at the tree and everything at the SELFTEST, which is where it is
enforced. That is the honest statement of what this shape is for: it keeps the
arm's SCOPE from drifting, and the day a citation like `wz-*` arrives it is the
difference between an answer and a coincidence.

⚠ The oracle is the tracked store's `inventory_entries` KEYS and nothing else.
Not its reasons, not its changelog, not `mnemosyne-cli`. The prose in that file
mentions these very tokens, so reading the store as TEXT would resolve every one
of them against the sentence citing it -- the vacuity this gate's header opens
with, rebuilt one file over. Reading a structured field is what keeps the arm
honest, and it also keeps this gate free of a binary that Layer C0 would then
have to guarantee.

⚠⚠ `scripts/**` IS NOT IN THE CORPUS, and leaving it in was measured to make
this whole gate vacuous. With every tracked text file in the corpus, all 163
REASON tokens "resolved" -- because a token resolves against THE VERY SENTENCE
CITING IT. That is R2131's recorded defect arriving from a new direction, and
the control that caught it is in the selftest: an invented token must not
resolve.

## The BUDGET, and why it is a ratchet rather than an exemption

Seventeen REASON tokens across six files resolve nowhere today. They are real
citations of things this resolver has no arm for -- upstream crate names
(`zenoh-transport`), upstream paths (`network/request.rs`), atom-id globs
(`platform-*`), composites (`QoSType::{D_FLAG, F_FLAG}`), a shell command
(`west build`). Forcing them red would be forcing a WRONG verdict, and naming
them in an exemption list would be writing the escape hatch item 566 warned
against in the same breath as the item.

So they are a per-file BUDGET, on `C1bz`'s contract exactly: a count ABOVE
budget is a citation this change added -- fix the citation, never the budget --
and a count BELOW it is one the change repaired, which lowers the budget in
that same commit. The number can reach zero, and the arms that would take it
there are the next round's, not a list this one writes.

## What this deliberately does NOT reach, stated rather than left implicit

DOCSTRINGS AND COMMENTS. The population is the string VALUES of tables, because
that is where a claim is machine-readable data rather than narration, and it is
where a gate's own vocabulary lives. A backtick in a module docstring -- this
file's own header included -- is prose, and prose about a gate is checked by
the reader, not here. `prose_dep_graph_gate.py` and `prose_build_closure_gate.py`
hold parts of that other surface; the rest is unmeasured and this sentence is
the admission rather than a claim of coverage.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import rust_comments  # noqa: E402  -- after the path insert that finds it

ROOT = pathlib.Path(__file__).resolve().parents[2]
GATES = "scripts/lib"
STORE = "docs/.atomic/workspace.atomic.json"

# An inventory id is lowercase words joined by hyphens; a CITATION of a family
# of them adds glob characters and nothing else. Anything carrying whitespace,
# an underscore, a capital or a regex metacharacter is some other kind of
# token and must reach the arm that owns it -- see the header for the three
# that a looser shape swallowed.
INVENTORY_GLOB = re.compile(r"^[a-z0-9-]*[*?\[\]][a-z0-9*?\[\]-]*$")

# The `re` entry points whose FIRST argument is a pattern. `split` and `sub`
# are here and `str.split` is not, which is why the check below insists the
# call's receiver is the `re` module by name: `_FIXTURE_SRC.split(...)` looked
# like a pattern use to the first draft, and `re.sub(P, "", _FIXTURE_SRC)`
# looked like one to the second. Only argument ZERO is the pattern.
RE_FUNCS = frozenset(
    {"compile", "search", "match", "fullmatch", "findall", "finditer", "sub", "subn", "split"}
)

# R2213 — citations that resolve NOWHERE today, per file. See the header: a
# ratchet, not an exemption. Each of these is a real claim about something this
# resolver has no arm for yet; the arms are the work, the numbers are the
# holding pattern, and both directions are enforced.
BUDGET = {
    # R2214 — `apfull_membership.py` LEFT this table. Its three citations were
    # `platform-*` / `runtime-*` / `api-compat-*`, globs over the store's
    # inventory ids, and the arm that reads that field resolves all three. The
    # ratchet is what made the removal compulsory rather than optional: with
    # the arm in and the row still at 3, this gate went red in the OTHER
    # direction and named the number to write.
    # `west build` -- a shell command of the Zephyr toolchain.
    "apt_package_census.py": 1,
    # `#[must_use] Discarded` -- an attribute and a type read as one token.
    "discard_site_lint.py": 2,
    # Upstream names and upstream paths: `zenoh-transport`, `WCodec`,
    # `network/request.rs`, plus expression-shaped citations like
    # `n.to_bytes_le()` and `QoSType::{D_FLAG, F_FLAG}`.
    "dissect_name_census.py": 9,
    # A regex fragment interpolated into another pattern rather than passed to
    # `re` directly, so the REGEX arm cannot see it.
    "expired_blocker_lint.py": 1,
    # R2214 — `verdict_leg_mutation.py` LEFT this table too, and not because an
    # arm was added: its citation was STALE. It named `link::strip_transport`,
    # which this tree has never held; the function that returns the
    # `SkipReason` the sentence is about is `link::decapsulate`. That is the
    # class this gate was built for, found on its first day, and the fix is the
    # one the ratchet's own message names -- correct the citation, never the
    # budget.
}


class Fatal(Exception):
    """A derivation that cannot be made. Never a silent pass."""


def tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [p for p in out.split("\0") if p]


def _inventory_ids() -> frozenset[str]:
    """The store's inventory ids, read as a STRUCTURED FIELD.

    Keys only. The store also holds every inventory reason and every changelog
    entry this repository has ever written, and those name the very tokens an
    inventory glob cites -- so reading the file as text would resolve each of
    them against the sentence citing it. That is the vacuity the header opens
    with, and taking a field rather than a blob is what keeps it out.

    A missing or unreadable store is FATAL rather than an empty set: an arm
    that cannot reach its oracle must not answer "resolves nowhere" and let a
    true citation go red, nor answer "resolves" and let a false one pass.
    """
    path = ROOT / STORE
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise Fatal(
            f"the inventory oracle {STORE} could not be read ({exc}); the "
            "inventory-glob arm has no input and must not guess in either "
            "direction."
        ) from exc
    entries = data.get("inventory_entries")
    if isinstance(entries, dict):
        ids = frozenset(entries)
    elif isinstance(entries, list):
        ids = frozenset(
            e.get("id") or e.get("inventory_id") for e in entries if isinstance(e, dict)
        ) - {None}
    else:
        raise Fatal(f"{STORE} holds no `inventory_entries` this arm can read.")
    if not ids:
        raise Fatal(
            f"{STORE} reports an EMPTY inventory. Every glob would resolve "
            "nowhere for the wrong reason, which reads as a citation defect."
        )
    return ids


class Corpus:
    """What a claim may be answered by, and nothing else.

    Built once. `scripts/**` is absent by construction rather than by a filter
    somebody could relax: see the header for what including it measured.
    """

    def __init__(self, paths: list[str]) -> None:
        self.paths = frozenset(paths)
        self.tops = frozenset(p.split("/", 1)[0] for p in paths if "/" in p)
        code: list[str] = []
        whole: list[str] = []
        for path in paths:
            if not path.startswith("crates/") or not path.endswith((".rs", ".h", ".c")):
                continue
            try:
                raw = (ROOT / path).read_text(errors="replace")
            except OSError:
                continue
            code.append(rust_comments.strip_comments(raw))
            whole.append(raw)
        self.code = "\n".join(code)
        self.whole = "\n".join(whole)
        self.files = len(code)
        self.inventory = _inventory_ids()

    def resolve(self, token: str, siblings: frozenset[str]) -> str | None:
        if token in siblings:
            return "sibling row"
        if "/" in token and not any(c.isspace() for c in token):
            if token.split("/", 1)[0] in self.tops:
                if token in self.paths:
                    return "tracked path"
                if any(c in token for c in "*?[") and any(
                    fnmatch.fnmatch(p, token) for p in self.paths
                ):
                    return "tracked path"
                return None
        if INVENTORY_GLOB.match(token):
            if any(fnmatch.fnmatch(i, token) for i in self.inventory):
                return "inventory ids"
            return None
        needle = token.split("::")[-1]
        haystack = self.whole if " " in token else self.code
        return "crates source" if needle in haystack else None


# --------------------------------------------------------------------------
# the classifier -- three derivations, in the order they must run
# --------------------------------------------------------------------------


def _loads(node: ast.AST, pool: set[str]) -> set[str]:
    return {
        s.id
        for s in ast.walk(node)
        if isinstance(s, ast.Name) and s.id in pool and isinstance(s.ctx, ast.Load)
    }


def selftest_closure(tree: ast.Module) -> set[str]:
    """Functions reachable from the `--selftest` BRANCH, by call graph.

    Seeded from the branch and not from a name: a function called `selftest`
    that nothing dispatches to is not a selftest, and one called `_probe` that
    the branch calls is.
    """
    funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    seeds: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and "selftest" in ast.dump(node.test):
            for stmt in node.body:
                seeds |= _loads(stmt, set(funcs))
    closure = set(seeds)
    stack = list(seeds)
    while stack:
        name = stack.pop()
        if name not in funcs:
            continue
        for called in _loads(funcs[name], set(funcs)):
            if called not in closure:
                closure.add(called)
                stack.append(called)
    return closure


def _regex_tables(tree: ast.Module, assigns: dict[str, ast.Assign]) -> set[str]:
    out: set[str] = set()
    for name, node in assigns.items():
        for sub in ast.walk(node.value):
            if _is_re_call(sub):
                out.add(name)
    for node in ast.walk(tree):
        if _is_re_call(node) and node.args:
            out |= _loads(node.args[0], set(assigns))
    return out


def _is_re_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in RE_FUNCS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "re"
    )


def _reader_functions(tree: ast.Module, name: str, seen: set[str] | None = None) -> set[str]:
    """Top-level functions reaching `name`, THROUGH module-level composition."""
    seen = seen or set()
    if name in seen:
        return set()
    seen.add(name)
    funcs: set[str] = set()
    tables: set[str] = set()
    for top in tree.body:
        if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _loads(top, {name}):
                funcs.add(top.name)
        elif isinstance(top, ast.Assign) and _loads(top.value, {name}):
            for target in top.targets:
                if isinstance(target, ast.Name):
                    tables.add(target.id)
    for table in tables:
        funcs |= _reader_functions(tree, table, seen)
    return funcs


def sibling_keys(tree: ast.Module) -> frozenset[str]:
    """Every string that is a KEY or a member of some UPPERCASE table here."""
    keys: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id.isupper() for t in node.targets):
            continue
        for sub in ast.walk(node.value):
            if isinstance(sub, ast.Dict):
                keys |= {
                    k.value for k in sub.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)
                }
            elif isinstance(sub, (ast.Set, ast.List, ast.Tuple)):
                keys |= {
                    e.value for e in sub.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
                }
    return frozenset(keys)


def classify(tree: ast.Module) -> dict[str, tuple[str, list[str]]]:
    """Table name -> (class, backticked tokens), for the tables that carry any."""
    assigns: dict[str, ast.Assign] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    assigns[target.id] = node
    regexy = _regex_tables(tree, assigns)
    closure = selftest_closure(tree)
    out: dict[str, tuple[str, list[str]]] = {}
    for name, node in assigns.items():
        tokens = [
            token
            for sub in ast.walk(node.value)
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str)
            for token in re.findall(r"`([^`]+)`", sub.value)
        ]
        if not tokens:
            continue
        if name in regexy:
            out[name] = ("REGEX", tokens)
            continue
        readers = _reader_functions(tree, name)
        fixture = bool(readers) and bool(closure) and readers <= closure
        out[name] = ("FIXTURE" if fixture else "REASON", tokens)
    return out


# --------------------------------------------------------------------------


def survey(corpus: Corpus, paths: list[str]) -> tuple[dict[str, int], dict[str, list[str]], int]:
    """(class counts, per-file unresolved tokens, tables seen)."""
    counts = {"REASON": 0, "FIXTURE": 0, "REGEX": 0}
    unresolved: dict[str, list[str]] = {}
    tables = 0
    for path in paths:
        if not path.startswith(f"{GATES}/") or not path.endswith(".py"):
            continue
        try:
            tree = ast.parse((ROOT / path).read_text(errors="replace"))
        except (OSError, SyntaxError):
            continue
        siblings = sibling_keys(tree)
        for _name, (kind, tokens) in classify(tree).items():
            tables += 1
            counts[kind] += len(tokens)
            if kind != "REASON":
                continue
            missing = [t for t in tokens if corpus.resolve(t, siblings) is None]
            if missing:
                unresolved.setdefault(pathlib.Path(path).name, []).extend(missing)
    return counts, unresolved, tables


def run() -> int:
    paths = tracked()
    corpus = Corpus(paths)
    if corpus.files == 0:
        raise Fatal(
            "the corpus holds no crates source, so every identifier claim would "
            "resolve nowhere for the wrong reason."
        )
    counts, unresolved, tables = survey(corpus, paths)
    if sum(counts.values()) == 0:
        raise Fatal(
            "no gate table carries a backticked token at all. The population is "
            "derived from the tables' own backticks; zero of them means this "
            "gate is checking nothing and reporting green."
        )

    print(
        f"gate-reason-claims: {tables} table(s) carrying "
        f"{sum(counts.values())} backticked token(s) -- "
        f"{counts['REASON']} REASON, {counts['FIXTURE']} FIXTURE, "
        f"{counts['REGEX']} REGEX; corpus is {corpus.files} crates file(s), "
        f"scripts/** deliberately absent"
    )

    findings: list[str] = []
    for name, missing in sorted(unresolved.items()):
        budget = BUDGET.get(name, 0)
        if len(missing) > budget:
            findings.append(
                f"{name}: {len(missing)} unresolved citation(s), budget {budget} "
                f"-- {sorted(set(missing))[:4]}. A count above budget is a "
                f"citation this change ADDED: fix the citation, never the budget."
            )
    for name, budget in sorted(BUDGET.items()):
        actual = len(unresolved.get(name, []))
        if actual < budget:
            findings.append(
                f"{name}: {actual} unresolved citation(s) against a budget of "
                f"{budget} -- the change REPAIRED one, so lower the budget to "
                f"{actual} in this same commit or the ratchet stops turning."
            )

    if findings:
        print("gate-reason-claims: FAIL", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    spent = sum(len(v) for v in unresolved.values())
    print(
        f"  budget: {spent} citation(s) resolve nowhere, across "
        f"{len(unresolved)} file(s), exactly as pinned"
    )
    return 0


# --------------------------------------------------------------------------
# selftest -- every derivation driven by a fixture that must move it
# --------------------------------------------------------------------------


def fail(message: str) -> int:
    print(f"gate-reason-claims: SELFTEST FAIL -- {message}", file=sys.stderr)
    return 1


def _classes(source: str) -> dict[str, str]:
    return {name: kind for name, (kind, _t) in classify(ast.parse(source)).items()}


def selftest() -> int:
    # A regex whose ONLY reader sits inside the selftest closure. The reader
    # test would call it a fixture; the shape test must win, and this is the
    # shape `REASON_BACKTICK` really has in the tree.
    regex_in_selftest = (
        "import re\n"
        "PAT = r'`([^`]+)`'\n"
        "def helper(s):\n"
        "    return re.findall(PAT, s)\n"
        "def selftest():\n"
        "    return helper('x')\n"
        "if args.selftest:\n"
        "    selftest()\n"
    )
    got = _classes(regex_in_selftest)
    if got.get("PAT") != "REGEX":
        return fail(f"a regex read only from the selftest was classed {got.get('PAT')!r}")

    # A fixture assembled into ANOTHER fixture at module level: the direct
    # reader is `<module>`, and only following the chain reaches the closure.
    chained = (
        "SRC = 'a `first` token'\n"
        "FILES = {'src': SRC}\n"
        "def _selftest():\n"
        "    return FILES\n"
        "if args.selftest:\n"
        "    _selftest()\n"
    )
    got = _classes(chained)
    if got.get("SRC") != "FIXTURE":
        return fail(f"a fixture composed into another was classed {got.get('SRC')!r}")

    # The same table, read by production code as well: it stops being a fixture
    # the moment anything outside the closure reads it.
    escaped = chained.replace("def _selftest():", "def main():\n    return FILES\ndef _selftest():")
    got = _classes(escaped)
    if got.get("SRC") != "REASON":
        return fail(f"a table read outside the closure was classed {got.get('SRC')!r}")

    # No selftest in the module at all: the fixture class is empty by
    # construction, and a table must not be granted it by default.
    plain = "TABLE = {'k': 'cites `something`'}\ndef main():\n    return TABLE\n"
    got = _classes(plain)
    if got.get("TABLE") != "REASON":
        return fail(f"a table in a module with no selftest was classed {got.get('TABLE')!r}")

    # `.split` is a str method too, and `re.sub(P, '', SUBJECT)` passes its
    # subject as argument TWO. Neither makes a table a pattern.
    not_a_pattern = (
        "import re\n"
        "SUBJ = 'a `token` here'\n"
        "def main():\n"
        "    return re.sub(r'x', '', SUBJ) + SUBJ.split(',')[0]\n"
    )
    got = _classes(not_a_pattern)
    if got.get("SUBJ") != "REASON":
        return fail(f"a regex SUBJECT was classed {got.get('SUBJ')!r}")

    # The corpus control, which is the whole reason `scripts/**` is out: an
    # invented token must resolve NOWHERE, and a real one must resolve.
    corpus = Corpus(tracked())
    if corpus.resolve("ZzQqInventedTokenXx", frozenset()) is not None:
        return fail("an invented token resolved; the corpus answers anything")
    if corpus.resolve("crates/wz-capture/src/agg.rs", frozenset()) != "tracked path":
        return fail("a real tracked path did not resolve as one")
    if corpus.resolve("a sibling", frozenset({"a sibling"})) != "sibling row":
        return fail("a sibling row key did not resolve as one")
    if corpus.resolve("deploy/*.nosuchext", frozenset()) is not None:
        return fail("a glob matching nothing resolved")

    # R2214 — the inventory-glob arm, both directions and its SHAPE.
    if corpus.resolve("platform-*", frozenset()) != "inventory ids":
        return fail("a glob over real inventory ids did not resolve as one")
    if corpus.resolve("zzqq-nosuch-*", frozenset()) is not None:
        return fail("an inventory glob matching NOTHING resolved; the arm passes anything")
    # The three tokens a looser shape swallowed. None of them is a claim about
    # the inventory, and each must reach the arm that owns it instead.
    for other in ("#[must_use] Discarded", "*lost +=", r"((?:z|ze|zc|zp)_[A-Za-z0-9_]*\*?)"):
        if INVENTORY_GLOB.match(other):
            return fail(f"{other!r} was claimed by the inventory-glob shape")

    print("gate-reason-claims: selftest OK (13 derivations driven)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="every backticked token in a gate's own tables must exist"
    )
    parser.add_argument("--selftest", action="store_true", help="drive each derivation")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    try:
        return run()
    except Fatal as exc:
        print(f"gate-reason-claims: FAIL -- {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
