#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
r"""R3172 (no register item) -- an e2e barrier must not wait on a string that no
producer in the tree can print.

The citation is `no register item` for the reason `debt_plane_census.py` gives
for its own: the item this answers for -- unregistered open-debt item 777 --
lives in an agent-memory register outside this repository, which has no store
id for `gate_provenance_lint.py` to resolve. Naming it in prose here and
`no register item` in the citation is the honest pair.

## What generated the defect

`wz_plugin_dynamic_loading_pico.rs` waited 15 seconds for `plugin load failed`
on the demo's stderr. A host change reworded the line to `plugin '{declared}'
stays Declared -- load failed:`; the host still refused correctly and still
logged, and the test timed out on a string nothing printed. The test is
`#[ignore]`d and only a hosted lane runs it with `--ignored`, so the first
evidence was a red hosted job, twice, for two different causes.

The string lives in two crates that share no definition and that cannot be made
to: `wz-ap-demo` has a `[[bin]]` and no `[lib]`, and `wz-integration-tests`
spawns its binary by path on purpose. "One constant, both sides" would need a lib
target and a dependency edge that break that boundary. The answer is a gate over
the population, and this is it.

## The population

Every needle handed to `wait_for_substring`, and to any wrapper that forwards one
of its own parameters into it (derived to a fixed point, so `wait_for_marker`,
`wait_for_line` and the `wait` methods are in it without being listed). A needle
is read as a literal, as a `format!` template (each literal piece graded), or as
an identifier resolved to a `const`/`let` of one of those in the same file. An
argument that is none of these is UNREADABLE and fails the gate: a population that
shrinks by what the reader cannot parse is the shape this gate exists to catch.

## What counts as a producer

Text some binary in this tree can print:

  * the string literals of `crates/*/src/**` -- `#[cfg(test)]` items and
    test-only modules excluded, because a unit test asserting a message must not
    be what makes a barrier on that message look produced -- of every crate that
    is not test support;
  * every string literal of every tracked C source and of the vendored zenoh-pico
    tree (the foreign CLI the e2e lanes drive);
  * C probe programs embedded in test files (a Rust literal carrying `printf(` or
    an `#include`).

A producer literal is a TEMPLATE: split at its placeholders (`{..}` in Rust, `%..`
in C) into literal segments with a value between each pair.

## Why the match is a substring of an output and not a regex with a wildcard

R2676 built this instrument once with a catch-all arm; it classified all 164
literal needles as templates and reported zero orphans, on a tree with a proven
orphan. A wildcard between segments accepts anything. So the test is exact: the
needle must be a substring of some string the template can print, where a
placeholder prints ONE token -- up to 40 characters and no whitespace -- and at
least two characters of the needle must come from the template's own literal
text. A template with fewer than eight literal characters in all (`{}: {}`) proves
nothing about any needle and is not a producer. The search is gated on a shared
three-character run of literal text, because the matcher is costly per template.

Measured, and the reason for the no-whitespace rule rather than a looser one:
the R2676 needle `plugin load failed` against that line's template
`plugin '{declared}' stays Declared -- load failed:` is NOT covered, and with a
wildcard that may contain spaces it would have been, through
`<anything> failed`.

## What is explicitly NOT claimed

A needle can be covered by text that is printed somewhere other than where the
test is looking (a literal in an unrelated module). Coverage is a necessary
condition for the barrier to ever be satisfiable, not a sufficient one, and the
needles that rest on three or fewer literal characters are counted every run so
the weak ones are visible.

Two declarations exist for what coverage cannot reach, written on a comment line
within twelve lines above the call:

  `// barrier-producer: <path> @ "<template>"` -- the producer is a wz literal the
    run above could not gate (the needle shares no three-character run with it,
    like `(unixpipe)` against `listening on {} ({})`). The gate checks that the
    file holds that literal and that the needle is covered by exactly that
    template, so the declaration is as strong as the match, and a producer
    reworded away fails it.
  `// barrier-origin: <kind> "<needle>"` -- the producer is a program this tree
    does not contain (zenohd, a zenoh-c or zenoh-ext example), or the needle is a
    value the test itself sent (`test-payload`). The quoted text must equal the
    needle, and a foreign kind must be a program the file itself names, so a
    declaration outlives neither a reworded needle nor a changed harness.

Exit codes: 0 green, 1 a finding, 2 the gate cannot see its subject.
"""
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lib"))
import crossimpl_corpus  # noqa: E402
import rust_comments  # noqa: E402
import silent_skip_gate  # noqa: E402

BASE_WAIT = "wait_for_substring"
VALUE_MAX = 80            # a placeholder prints one token this long, at most
MIN_SEARCH_LITERAL = 4    # characters a needle must take from literal text when the
#                           whole tree is searched for its producer
MIN_LITERAL = 2           # the same, for a template a human named for that needle
MIN_PRODUCER_LITERAL = 8  # a template with less says nothing about any needle
STRONG = 4                # stop searching once a template accounts for this many
CAND_MAX = 400            # a three-character run held by more templates than this says nothing
WEAK_BELOW = 4            # needles resting on fewer literal characters are counted

RUST_PH = re.compile(r"\{[^{}]*\}")
C_PH = re.compile(
    r"%[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|z|j|t|L)?[diouxXeEfFgGaAcspn]")
C_EXT = (".c", ".h", ".cpp", ".hpp", ".inc")

FOREIGN_KINDS = {
    "zenohd": ("zenohd",),
    "zenoh-c": ("zenoh_c", "zenoh-c", "libzenohc"),
    "zenoh-ext": ("zenoh_ext", "zenoh-ext", "z_view_size", "z_member"),
    "test-payload": (),
}
ORIGIN = re.compile(
    r'//\s*barrier-origin:\s*([a-z-]+)\s+"((?:[^"\\]|\\.)*)"'
    r'(?:\s*--\s*`([^`]+)`\s*@\s*`([^`]+)`)?')
PRODUCER = re.compile(
    r'//\s*barrier-producer:\s*(\S+)\s*@\s*"((?:[^"\\]|\\.)*)"\s+for\s+"((?:[^"\\]|\\.)*)"')


# ── literals ─────────────────────────────────────────────────────────

def string_literals(text):
    """(start, end, content, raw) of every string literal in comment-stripped text."""
    out, i, n = [], 0, len(text)
    raw_open = re.compile(r'b?r(#*)"')
    while i < n:
        c = text[i]
        if c == "'":
            if i + 2 < n and (text[i + 1] == "\\" or text[i + 2] == "'"):
                j = i + 1
                while j < n:
                    if text[j] == "\\":
                        j += 2
                        continue
                    if text[j] == "'":
                        j += 1
                        break
                    j += 1
                i = j
                continue
            i += 1
            continue
        if c in "br" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            m = raw_open.match(text, i)
            if m:
                close = '"' + m.group(1)
                e = text.find(close, m.end())
                e = n if e < 0 else e
                out.append((i, e + len(close), text[m.end():e], True))
                i = e + len(close)
                continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            out.append((i, j + 1, text[i + 1:j], False))
            i = j + 1
            continue
        i += 1
    return out


def value_of(content, raw):
    return content if raw else crossimpl_corpus.unescape_rust_string(content)


def rust_segments(text):
    text = text.replace("{{", "\x01").replace("}}", "\x02")
    return [p.replace("\x01", "{").replace("\x02", "}") for p in RUST_PH.split(text)]


def c_segments(text):
    text = text.replace("%%", "\x01")
    return [p.replace("\x01", "%") for p in C_PH.split(text)]


# ── what a template can print ────────────────────────────────────────

def coverage(needle, segs, spaces=False):
    """`coverage_exact`, capped at STRONG, by a bit-parallel NFA.

    The exact matcher is the definition and the bit-parallel one is how it is run
    over thousands of templates (about forty times faster): one machine word per
    literal-count layer, a bit per position in the template. A needle longer than
    VALUE_MAX goes to the exact one, because the length limit on a placeholder is
    the only thing the bit-parallel form does not track (it cannot bind below that
    length). `--selftest` asserts the two agree on every fixture.

    `spaces` lets a placeholder print whitespace: used only for a template a human
    DECLARED beside a barrier, never for the search over the tree.
    """
    if len(needle) > VALUE_MAX:
        return min(coverage_exact(needle, segs, spaces), STRONG)
    lit_mask, v_mask, pos = {}, 0, 0
    for k, seg in enumerate(segs):
        for c in seg:
            lit_mask[c] = lit_mask.get(c, 0) | (1 << pos)
            pos += 1
        if k < len(segs) - 1:
            v_mask |= 1 << pos
            pos += 1

    def closure(x):
        while True:
            y = x | ((x & v_mask) << 1)
            if y == x:
                return x
            x = y

    layers = [closure((1 << (pos + 1)) - 1)] + [0] * STRONG
    for ch in needle:
        lit = lit_mask.get(ch, 0)
        vv = v_mask if (spaces or not ch.isspace()) else 0
        nxt = [0] * (STRONG + 1)
        for k in range(STRONG + 1):
            nxt[min(k + 1, STRONG)] |= (layers[k] & lit) << 1
            nxt[k] |= layers[k] & vv
        layers = [closure(x) for x in nxt]
        if not any(layers):
            return 0
    for k in range(STRONG, -1, -1):
        if layers[k]:
            return k
    return 0


def coverage_exact(needle, segs, spaces=False):
    """Most characters of `needle` a producer template can account for from its
    own literal text, with every placeholder printing one token of at most
    VALUE_MAX non-space characters -- or 0 when it cannot print `needle` at all.

    An NFA over the template, read from ANY starting state, because a needle is a
    substring of an output. State: (item index, characters consumed by the
    placeholder it sits in). The score is the literal characters consumed, so a
    needle that lies wholly inside placeholders scores 0 and is not covered.
    """
    items = []
    for k, seg in enumerate(segs):
        items.extend(("L", c) for c in seg)
        if k < len(segs) - 1:
            items.append(("V", None))
    last = len(items)

    def closure(states):
        out = dict(states)
        todo = list(states)
        while todo:
            idx, cnt = todo.pop()
            if idx < last and items[idx][0] == "V":
                nxt = (idx + 1, 0)
                if nxt not in out or out[nxt] < out[(idx, cnt)]:
                    out[nxt] = out[(idx, cnt)]
                    todo.append(nxt)
        return out

    cur = closure({(i, 0): 0 for i in range(last + 1)})
    for ch in needle:
        nxt = {}
        for (idx, cnt), lit in cur.items():
            if idx >= last:
                continue
            kind, c = items[idx]
            if kind == "L":
                if c == ch and nxt.get((idx + 1, 0), -1) < lit + 1:
                    nxt[(idx + 1, 0)] = lit + 1
            elif (spaces or not ch.isspace()) and cnt < VALUE_MAX:
                if nxt.get((idx, cnt + 1), -1) < lit:
                    nxt[(idx, cnt + 1)] = lit
        cur = closure(nxt)
        if not cur:
            return 0
    return max(cur.values()) if cur else 0


class Producers:
    def __init__(self):
        self.blob_parts = []        # whole segments, for plain containment
        self.templates = []         # (origin, segs) with >=1 placeholder
        self.index = defaultdict(list)
        self.count = Counter()
        self._blob = None

    def add(self, origin, kind, segs):
        self.count[kind] += 1
        self.blob_parts.extend(segs)
        if len(segs) > 1 and sum(len(s) for s in segs) >= MIN_PRODUCER_LITERAL:
            ti = len(self.templates)
            self.templates.append((origin, segs))
            grams = set()
            for s in segs:
                grams.update(s[i:i + 3] for i in range(len(s) - 2))
            for g in grams:
                self.index[g].append(ti)

    def blob(self):
        if self._blob is None:
            self._blob = "\x00".join(self.blob_parts)
        return self._blob

    def cover(self, needle):
        """('plain'|'template', origin, literal_chars) or None."""
        if needle in self.blob():
            return ("plain", None, len(needle))
        # Candidates share a three-character run of literal text with the needle.
        # A run like `ing` is in thousands of templates and says nothing, so runs
        # held by more than CAND_MAX of them are skipped -- unless every run is that
        # common, when the least common one is used. The run that matters is often
        # NOT the rarest: a needle ending in an address has rare runs (`0.1`) that
        # belong to the value, not to the template that printed it.
        # A needle with no run in any template has no literal anchor worth grading
        # and is declared at the barrier instead.
        grams = sorted(
            {needle[i:i + 3] for i in range(len(needle) - 2)} & self.index.keys(),
            key=lambda g: len(self.index[g]))
        usable = [g for g in grams if len(self.index[g]) <= CAND_MAX] or grams[:1]
        seen, best, origin = set(), 0, None
        for g in usable:
            for ti in self.index[g]:
                if ti in seen:
                    continue
                seen.add(ti)
                got = coverage(needle, self.templates[ti][1])
                if got > best:
                    best, origin = got, self.templates[ti][0]
            if best >= STRONG:
                break
        if best >= min(MIN_SEARCH_LITERAL, len(needle)) and best > 0:
            return ("template", origin, best)
        return None


# ── the tree ─────────────────────────────────────────────────────────

_VIEWS = {}


def views(rel, raw=None):
    """(raw, literals-kept, literals-blanked) of one file, computed once: the
    producer reader and the barrier reader both need them and stripping is the
    dominant cost of this gate."""
    if rel not in _VIEWS:
        if raw is None:
            raw = (ROOT / rel).read_text(errors="replace")
        _VIEWS[rel] = (raw, rust_comments.strip_comments(raw),
                       rust_comments.strip_comments(raw, blank_literals=True))
    return _VIEWS[rel]


def tracked(globs):
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--"] + globs,
        cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("git ls-files failed: " + out.stderr.strip())
    return [p for p in out.stdout.splitlines() if "/target/" not in p]


def crate_of(path):
    parts = Path(path).parts
    return parts[1] if len(parts) > 1 and parts[0] == "crates" else parts[0]


def is_test_support(crate):
    return crate == "wz-integration-tests" or crate.endswith("test-support") \
        or crate.endswith("-tests")


def test_spans(code):
    """Spans of items under `#[cfg(test)]` (a `mod`, a fn, an impl)."""
    spans = []
    for m in re.finditer(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]", code):
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
        if i >= len(code):
            continue
        if code[i] == "{":
            close = silent_skip_gate.match_close(code, i, "{", "}")
            spans.append((m.start(), close if close > 0 else len(code)))
        else:
            spans.append((m.start(), i))
    return spans


def test_module_files(path, code):
    """Files a `#[cfg(test)] mod name;` declaration points at."""
    out = set()
    p = ROOT / path
    for m in re.finditer(
            r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:pub\s+)?mod\s+(\w+)\s*;", code):
        name = m.group(1)
        out.add(p.parent / (name + ".rs"))
        out.add(p.parent / name / "mod.rs")
        out.add(p.parent / p.stem / (name + ".rs"))
    return out


PRINTF_IN_SCRIPT = re.compile(
    r'\b(?:printf|fprintf|puts|fputs|snprintf)\s*\(\s*'
    r'(?:[A-Za-z_][A-Za-z0-9_]*\s*,\s*)?"((?:[^"\\]|\\.)*)"')


def load_producers(rust_paths, c_paths, pico_root, script_paths=()):
    prod = Producers()
    # `scripts/build-zenoh-pico-cli.sh` PATCHES the vendored examples to print
    # `with priority:` and friends: that C lives in the script, as a heredoc, so a
    # printf format inside a shell script is a producer of the foreign CLI.
    for rel in script_paths:
        try:
            text = (ROOT / rel).read_text(errors="replace")
        except OSError:
            continue
        for m in PRINTF_IN_SCRIPT.finditer(text):
            prod.add(rel, "script", c_segments(value_of(m.group(1), False)))
    skipped_test_files = set()
    for rel in rust_paths:
        if "/src/" not in rel or is_test_support(crate_of(rel)):
            continue
        _raw, _lit, code = views(rel)
        skipped_test_files |= test_module_files(rel, code)
    for rel in rust_paths:
        if "/src/" not in rel or is_test_support(crate_of(rel)):
            continue
        if (ROOT / rel) in skipped_test_files or Path(rel).name == "tests.rs":
            continue
        _raw, lit, code = views(rel)
        spans = test_spans(code)
        for s, e, content, rawk in string_literals(lit):
            if any(a <= s < b for a, b in spans):
                continue
            prod.add(rel, "rust", rust_segments(value_of(content, rawk)))
    for rel in rust_paths:
        raw, lit, _code = views(rel)
        if "printf(" not in raw and "#include" not in raw:
            continue
        for s, e, content, rawk in string_literals(lit):
            if "printf(" in content or "#include" in content:
                body = value_of(content, rawk)
                for s2, e2, c2, r2 in string_literals(body):
                    prod.add(rel, "probe", c_segments(value_of(c2, r2)))
    c_files = [ROOT / p for p in c_paths]
    if pico_root is not None and pico_root.is_dir():
        c_files += [p for p in pico_root.rglob("*")
                    if p.is_file() and p.suffix in (".c", ".h")]
    for p in sorted(set(c_files)):
        try:
            text = rust_comments.strip_comments(p.read_text(errors="replace"))
        except OSError:
            continue
        for s, e, content, rawk in string_literals(text):
            prod.add(str(p.relative_to(ROOT)), "c", c_segments(value_of(content, False)))
    return prod


# ── the barriers ─────────────────────────────────────────────────────

def arg_spans(code, open_idx, close_idx):
    """(start, end) of each argument of a call, split on the BLANKED view (a
    bracket or a comma inside a string literal is data). A call with no arguments
    has no spans."""
    out, depth, start = [], 0, open_idx + 1
    for i in range(open_idx + 1, close_idx):
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append((start, i))
            start = i + 1
    if code[start:close_idx].strip():          # rustfmt's trailing comma adds none
        out.append((start, close_idx))
    return out


def call_args(code, lit, open_idx, close_idx):
    """The arguments of a call, cut from the literal-bearing view."""
    return [lit[a:b].strip() for a, b in arg_spans(code, open_idx, close_idx)]


def enclosing_calls(code, lo, p):
    """(name, open paren offset) of every call or macro whose parentheses contain
    offset `p`, innermost first, not looking before `lo`."""
    out, depth, i = [], 0, p - 1
    while i >= lo:
        c = code[i]
        if c in ")]}":
            depth += 1
        elif c in "([{":
            if depth:
                depth -= 1
            elif c == "(":
                m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*!?\s*$", code[max(lo, i - 80):i])
                out.append((m.group(1) if m else None, i))
        i -= 1
    return out


class Site:
    def __init__(self, path, line, fn, expr):
        self.path, self.line, self.fn, self.expr = path, line, fn, expr


class Src:
    def __init__(self, path, raw):
        self.path = path
        self.crate = crate_of(path)
        _raw, self.lit, self.code = views(path, raw)
        self.fns = silent_skip_gate.fn_table(self.code)
        for f in self.fns:
            f.params = []
            op = self.code.find("(", f.sig_start)
            if 0 <= op < f.body_open:
                cl = silent_skip_gate.match_close(self.code, op, "(", ")")
                if cl > 0:
                    for a in call_args(self.code, self.lit, op, cl):
                        name = a.split(":")[0].strip()
                        if name not in ("self", "&self", "&mut self", "mut self"):
                            f.params.append(re.sub(r"^(?:mut\s+)", "", name))

    def line(self, idx):
        return self.code.count("\n", 0, idx) + 1

    def calls(self, name):
        """(offset, args) of each call of `name(` that is not its definition."""
        for m in re.finditer(r"\b%s\s*\(" % re.escape(name), self.code):
            if re.search(r"fn\s+$", self.code[max(0, m.start() - 12):m.start()]):
                continue
            op = m.end() - 1
            cl = silent_skip_gate.match_close(self.code, op, "(", ")")
            if cl < 0:
                continue
            yield m.start(), call_args(self.code, self.lit, op, cl)

    def statement_span(self, idx):
        """(start, end) of the statement beginning at `idx`, ending at its `;`."""
        depth = 0
        for i in range(idx, len(self.code)):
            c = self.code[i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == ";" and depth <= 0:
                return (idx, i)
        return None

    def statement_after(self, idx):
        """Text from `idx` to the `;` that ends the statement, on the literal view."""
        sp = self.statement_span(idx)
        return self.lit[sp[0]:sp[1]].strip() if sp else None


def tuple_components(code, lit, arity, idx):
    """Component `idx` of every tuple LITERAL of `arity` in a text. A parenthesis
    after a name, `!`, `>` or a closing bracket is a call, not a tuple."""
    out = []
    for i, c in enumerate(code):
        if c != "(":
            continue
        prev = code[:i].rstrip()[-1:]
        if prev and (prev.isalnum() or prev in "_!>)]"):
            continue
        close = silent_skip_gate.match_close(code, i, "(", ")")
        if close < 0:
            continue
        spans = arg_spans(code, i, close)
        if len(spans) == arity:
            a, b = spans[idx]
            out.append(lit[a:b].strip())
    return out


def base_needle_index(srcs):
    """{crate: needle index} read off the definition of the base wait fn."""
    out = {}
    for s in srcs:
        for f in s.fns:
            if f.name == BASE_WAIT and "needle" in f.params:
                out[s.crate] = f.params.index("needle")
    return out


# A value the TEST hands to a program or to the node under test is not text a
# producer prints, it is text the test chose: `-v payload` to a foreign z_put, a
# value given to a publisher. Waiting for it to come back is a barrier on the
# round trip, and no tree literal can account for it. The sinks are the calls that
# carry such a value out of the test; a fn of this crate that passes a parameter on
# to one of them is followed, so `spawn_publisher(&z_pub, key, value)` counts.
SINKS = {"arg", "args", "env", "envs", "write_all", "write", "put", "publish",
         "send", "push", "reply"}
CONST_RE = re.compile(
    r"\b(?:const|static)\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*&(?:'static\s+)?str\s*=\s*")


class Tree:
    """The readable Rust files, with what the barrier reader needs to know about
    them: which fns exist, which `&str` consts, which fns wait for a needle."""

    def __init__(self, srcs):
        self.srcs = srcs
        self.fn_by_name = defaultdict(list)
        self.consts = defaultdict(list)
        self.aliases = {}                   # (file, local name) -> imported name
        for s in srcs:
            for m in re.finditer(r"\buse\s+[\w:]*?(\w+)\s+as\s+(\w+)\s*;", s.code):
                self.aliases[(s.path, m.group(2))] = m.group(1)
            for f in s.fns:
                self.fn_by_name[(s.crate, f.name)].append((s, f))
            for m in CONST_RE.finditer(s.code):
                rhs = s.statement_after(m.end())
                if rhs:
                    self.consts[(s.crate, m.group(1))].append((s, rhs))
        self.base = base_needle_index(srcs)
        self._flow = {}
        self.wrappers, self.echo_fns = self._derive()

    def flows_to_sink(self, s, f, ident, depth=0):
        key = (s.path, f.body_open, ident)
        if key in self._flow:
            return self._flow[key]
        self._flow[key] = False           # a cycle answers "no" rather than looping
        found = False
        body = s.code[f.body_open:f.body_close]
        for m in re.finditer(r"(?<![\w.])%s\b" % re.escape(ident), body):
            p = f.body_open + m.start()
            for name, op in enclosing_calls(s.code, f.body_open, p):
                if name in SINKS:
                    found = True
                    break
                if depth < 3:
                    cl = silent_skip_gate.match_close(s.code, op, "(", ")")
                    spans = arg_spans(s.code, op, cl) if cl > 0 else []
                    for k, (a, b) in enumerate(spans):
                        if a <= p < b:
                            for cs, cf in self.fn_by_name.get((s.crate, name), ()):
                                if k < len(cf.params) and self.flows_to_sink(
                                        cs, cf, cf.params[k], depth + 1):
                                    found = True
                if found:
                    break
            if found:
                break
        self._flow[key] = found
        return found

    def _derive(self):
        """(wrappers, echo fns), to a fixed point. A wrapper forwards one of its
        own parameters as a needle and uses it for nothing else the test sends; an
        echo fn forwards a parameter the test ALSO sends, so its callers hand it
        values and are not barriers on producer text."""
        wrappers, echo = {}, {}
        changed = True
        while changed:
            changed = False
            for s in self.srcs:
                known = {n: i for (c, n), (i, _p) in wrappers.items() if c == s.crate}
                known.update({n: i for (c, n), (i, _p) in echo.items() if c == s.crate})
                if s.crate in self.base:
                    known[BASE_WAIT] = self.base[s.crate]
                for f in s.fns:
                    k = (s.crate, f.name)
                    if k in wrappers or k in echo or f.name == BASE_WAIT:
                        continue
                    for name, idx in known.items():
                        hit = None
                        for m in re.finditer(r"\b%s\s*\(" % re.escape(name),
                                             s.code[f.body_open:f.body_close]):
                            op = f.body_open + m.end() - 1
                            cl = silent_skip_gate.match_close(s.code, op, "(", ")")
                            if cl < 0:
                                continue
                            args = call_args(s.code, s.lit, op, cl)
                            if idx < len(args):
                                arg = args[idx].lstrip("&*").strip()
                                if arg in f.params:
                                    hit = arg
                                    break
                        if hit is None:
                            continue
                        entry = (f.params.index(hit), len(f.params))
                        if self.flows_to_sink(s, f, hit):
                            echo[k] = entry
                        else:
                            wrappers[k] = entry
                        changed = True
                        break
        return wrappers, echo

    def lookup_const(self, s, name):
        local = [(cs, rhs) for cs, rhs in self.consts.get((s.crate, name), ())
                 if cs is s]
        return local or self.consts.get((s.crate, name), [])

    def pieces(self, text):
        """Every string literal in `text` as needle material: a plain literal whole,
        a format template as the literal pieces between its placeholders."""
        out = []
        for _s, _e, content, raw in string_literals(text):
            value = value_of(content, raw)
            if "{" in value or "}" in value:
                out.extend(x for x in rust_segments(value) if x)
            elif value:
                out.append(value)
        return out

    def resolve(self, s, expr, enclosing, at, depth=0):
        """('ok', texts), ('forwarded', []), ('echo', []) or None when unreadable.

        'forwarded' is a parameter of the wrapper the call sits in (its callers are
        graded), 'echo' a value the test itself sends (nothing to grade). The
        readable forms are exactly the ones the tree uses: a literal or `format!`,
        an identifier bound by `let`, by `for .. in [..]`, to a parameter or to a
        `const`, an array of those, a call to a fn of this crate (its literals),
        and an `if`/`else` of any of them. Anything else is None, never a guess.
        """
        e = re.sub(r"^&+\s*(?:mut\s+)?", "", expr.strip())
        for _ in range(3):
            e = re.sub(r"\.(?:to_string|to_owned|as_str|as_ref|into|clone)\(\)$", "", e).strip()
        if depth > 4:
            return None
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", e):
            return self._resolve_ident(s, e, enclosing, at, depth)
        if e.startswith("[") and e.endswith("]"):
            out, any_ok = [], False
            for a, b in arg_spans(e, 0, len(e) - 1):
                if not e[a:b].strip():
                    continue                  # the trailing comma rustfmt writes
                got = self.resolve(s, e[a:b], enclosing, at, depth + 1)
                if got is None:
                    return None
                if got[0] == "ok":
                    out.extend(got[1])
                    any_ok = True
            return ("ok", out) if any_ok else ("echo", [])
        pieces = self.pieces(e)
        for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.sub(
                r'"(?:[^"\\]|\\.)*"', '""', e)):
            for cs, cf in self.fn_by_name.get((s.crate, m.group(1)), ()):
                pieces.extend(self.pieces(cs.lit[cf.body_open:cf.body_close]))
        if pieces:
            return ("ok", pieces)
        # A literal that is empty (`""`, an accepting row's absent reason) is a
        # value the reader understood, not one it could not read.
        return ("ok", []) if string_literals(e) else None

    def _resolve_ident(self, s, e, enclosing, at, depth):
        if enclosing is not None and e in enclosing.params:
            if (s.crate, enclosing.name) in self.wrappers:
                return ("forwarded", [])
            if (s.crate, enclosing.name) in self.echo_fns \
                    or self.flows_to_sink(s, enclosing, e):
                return ("echo", [])
            return None
        lo = enclosing.body_open if enclosing is not None else 0
        name = re.escape(e)
        lets = list(re.compile(
            r"\blet\s+(?:mut\s+)?%s\s*(?::[^=;]+)?=\s*" % name).finditer(s.code, lo, at))
        fors = list(re.compile(
            r"\bfor\s+(?:mut\s+)?%s\s+in\s+" % name).finditer(s.code, lo, at))
        # A name bound inside a tuple pattern, `let (a, b) = ..` or
        # `for (a, b) in [(..), (..)]`: the value is the same component of every
        # tuple LITERAL in the right-hand side, never the whole table.
        tup_lets = list(re.compile(
            r"\blet\s*\(([^()]*\b%s\b[^()]*)\)\s*(?::[^=;]+)?=\s*" % name
        ).finditer(s.code, lo, at))
        tup_fors = list(re.compile(
            r"\bfor\s*\(([^()]*\b%s\b[^()]*)\)\s+in\s+" % name).finditer(s.code, lo, at))
        latest = max(lets[-1:] + fors[-1:] + tup_lets[-1:] + tup_fors[-1:],
                     key=lambda m: m.start(), default=None)
        if latest is not None:
            if latest in fors or latest in tup_fors:
                brace = s.code.find("{", latest.end())
                span = (latest.end(), brace) if brace > 0 else None
            else:
                span = s.statement_span(latest.end())
            if span is None:
                return None
            code_t, lit_t = s.code[span[0]:span[1]], s.lit[span[0]:span[1]].strip()
            if latest in tup_lets or latest in tup_fors:
                names = [re.sub(r"^mut\s+", "", n.strip())
                         for n in latest.group(1).split(",") if n.strip()]
                if e not in names:
                    return None
                code_c, lit_c = code_t, s.lit[span[0]:span[1]]
                bare = re.fullmatch(r"&?\s*([A-Za-z_][A-Za-z0-9_]*)", code_t.strip())
                if bare:
                    # `for (..) in TABLE`: the table is a `const`/`static` of any
                    # type, read at its definition.
                    tm = re.search(
                        r"\b(?:const|static)\s+%s\s*:[^=;]+=\s*" % re.escape(bare.group(1)),
                        s.code)
                    tspan = s.statement_span(tm.end()) if tm else None
                    if tspan is None:
                        return None
                    code_c, lit_c = s.code[tspan[0]:tspan[1]], s.lit[tspan[0]:tspan[1]]
                comps = tuple_components(code_c, lit_c, len(names), names.index(e))
                if not comps:
                    return None
                out = []
                for comp in comps:
                    got = self.resolve(s, comp, enclosing, latest.start(), depth + 1)
                    if got is None:
                        return None
                    if got[0] == "ok":
                        out.extend(got[1])
                return ("ok", out) if out else ("echo", [])
            got = self.resolve(s, lit_t, enclosing, latest.start(), depth + 1) \
                if lit_t else None
            if got is None:
                return None
            if got[0] == "ok" and enclosing is not None \
                    and self.flows_to_sink(s, enclosing, e):
                return ("echo", [])
            return got
        out = []
        for cs, rhs in self.lookup_const(s, self.aliases.get((s.path, e), e)):
            got = self.resolve(cs, rhs, None, 0, depth + 1)
            if got and got[0] == "ok":
                out.extend(got[1])
        if out and enclosing is not None and self.flows_to_sink(s, enclosing, e):
            return ("echo", [])           # a const the test hands to a program
        return ("ok", out) if out else None

    def needle_sites(self):
        sites, unresolved, skipped = [], [], Counter()
        for s in self.srcs:
            names = {}
            if s.crate in self.base:
                names[BASE_WAIT] = (self.base[s.crate], None)
            names.update({n: v for (c, n), v in self.wrappers.items() if c == s.crate})
            names.update({n: v for (c, n), v in self.echo_fns.items() if c == s.crate})
            for name, (idx, nparams) in names.items():
                for at, args in s.calls(name):
                    if nparams is not None and len(args) != nparams:
                        continue
                    if idx >= len(args):
                        continue
                    enclosing = silent_skip_gate.innermost(s.fns, at)
                    got = self.resolve(s, args[idx], enclosing, at)
                    site = Site(s.path, s.line(at), name, args[idx])
                    if got is None:
                        unresolved.append(site)
                        continue
                    kind, strings = got
                    if kind in ("forwarded", "echo"):
                        skipped[kind] += 1
                        continue
                    if (s.crate, name) in self.echo_fns:
                        skipped["echo"] += 1       # a caller of a send-and-wait fn
                        continue
                    for text in strings:
                        sites.append((site, text, kind))
        return sites, unresolved, skipped


def wait_wrappers(srcs):
    return Tree(srcs).wrappers


def find_needles(srcs, wrappers=None):
    return Tree(srcs).needle_sites()


# ── declarations ─────────────────────────────────────────────────────

class Declarations:
    """The `barrier-origin` / `barrier-producer` comments of ONE crate.

    A declaration anywhere in the crate covers every barrier in it that waits for
    the declared needle: `ZENOHD_LISTENER_LINE` is one constant six test files
    wait on, and a table of eight `Initial conf:` waits is one fact. The price of
    that reach is the other direction -- a declaration no barrier of the crate used
    is STALE and fails, so one cannot outlive the barrier it explained.
    """

    def __init__(self, files):
        """`files` is {path: raw text} for the crate."""
        self.origins = []     # [kind, needle, citation or None, used, path]
        self.producers = []   # [path, template, needle, used, declaring path]
        for path, raw in files.items():
            for m in ORIGIN.finditer(raw):
                self.origins.append([m.group(1),
                                     crossimpl_corpus.unescape_rust_string(m.group(2)),
                                     (m.group(3), m.group(4)) if m.group(3) else None,
                                     False, path])
            for m in PRODUCER.finditer(raw):
                self.producers.append([m.group(1),
                                       crossimpl_corpus.unescape_rust_string(m.group(2)),
                                       crossimpl_corpus.unescape_rust_string(m.group(3)),
                                       False, path])

    def origin(self, needle, site_raw):
        """The kind of a declaration that names this needle exactly, whose citation
        (when given) shares text with it, and -- for a program -- that the file the
        barrier is in actually names. The programs a file names are read OUTSIDE the
        declarations: `barrier-origin: zenohd` names zenohd by being one."""
        body = ORIGIN.sub("", site_raw)
        for d in self.origins:
            kind, quoted, cite, _used, _path = d
            if quoted != needle or kind not in FOREIGN_KINDS:
                continue
            tokens = FOREIGN_KINDS[kind]
            if tokens and not any(t in body for t in tokens):
                continue
            if cite and not (cite[1] in needle or needle in cite[1]):
                continue
            d[3] = True
            return kind
        return None

    def producer(self, needle, read_literals):
        """True when a declaration names THIS needle, its template covers it, and
        its file holds that template. `read_literals(path)` returns the file's
        producer literal values, or None when it is not a producer file.

        The declaration is tied to one needle on purpose. Whitespace is allowed in
        a declared template's values -- the human is attesting which template prints
        the needle, and `<anonymous peer>` has a space in it -- and that latitude
        would let any declaration cover any needle with two characters in common if
        it were not bound to the text it was written for.
        """
        for d in self.producers:
            path, quoted, declared_for, _used, _decl = d
            if declared_for != needle:
                continue
            literals = read_literals(path)
            if literals is None or not any(quoted in lit for lit in literals):
                continue
            segs = c_segments(quoted) if path.endswith(C_EXT) else rust_segments(quoted)
            if coverage(needle, segs, spaces=True) >= min(MIN_LITERAL, len(needle)) > 0:
                d[3] = True
                return True
        return False

    def stale(self):
        out = ["%s: `// barrier-origin: %s \"%s\"`" % (p, k, n)
               for k, n, _c, used, p in self.origins if not used]
        out += ["%s: `// barrier-producer: %s @ \"%s\" for \"%s\"`" % (decl, p, t, n)
                for p, t, n, used, decl in self.producers if not used]
        return out


def producer_literals(rel):
    """Literal values of a producer file (not test support, not test code)."""
    p = ROOT / rel
    if not p.is_file():
        return None
    if rel.endswith(C_EXT):
        text = rust_comments.strip_comments(p.read_text(errors="replace"))
        return [value_of(c, False) for _s, _e, c, _r in string_literals(text)]
    if "/src/" not in rel or is_test_support(crate_of(rel)):
        return None
    _raw, lit, code = views(rel)
    spans = test_spans(code)
    return [value_of(c, r) for s, _e, c, r in string_literals(lit)
            if not any(a <= s < b for a, b in spans)]


# ── the verdict ──────────────────────────────────────────────────────

def grade(srcs, producers, raw_by_path, read_literals=producer_literals):
    tree = Tree(srcs)
    wrappers = tree.wrappers
    sites, unresolved, skipped = tree.needle_sites()
    findings, tally, weak = [], Counter(), []
    by_crate = defaultdict(dict)
    for path, raw in raw_by_path.items():
        if "barrier-origin:" in raw or "barrier-producer:" in raw:
            by_crate[crate_of(path)][path] = raw
    decls = {c: Declarations(files) for c, files in by_crate.items()}
    for site, needle, kind in sites:
        if not needle.strip():
            continue
        got = producers.cover(needle)
        if got:
            tally[got[0]] += 1
            if got[0] == "template" and got[2] < WEAK_BELOW:
                weak.append((site.path, site.line, needle, got[2]))
            continue
        d = decls.get(crate_of(site.path))
        if d is not None and d.producer(needle, read_literals):
            tally["declared:producer"] += 1
            continue
        origin = d.origin(needle, raw_by_path[site.path]) if d is not None else None
        if origin:
            tally["declared:" + origin] += 1
            continue
        findings.append(
            "%s:%d  `%s(..)` waits for %r and no producer in the tree can print "
            "it: no literal or template of any non-test crate source, C source or "
            "embedded probe accounts for it. Either the producer's wording moved, "
            "or the producer is not in this tree -- then declare it in this file: "
            "// barrier-origin: <kind> \"%s\" [-- `<upstream path>` @ `<anchor>`] "
            "(kinds: %s), or, for a wz template the matcher cannot reach: "
            "// barrier-producer: <path> @ \"<template>\" for \"%s\""
            % (site.path, site.line, site.fn, needle, needle.replace('"', '\\"'),
               ", ".join(sorted(FOREIGN_KINDS)), needle.replace('"', '\\"')))
    # A declaration is only as good as the barrier it explains. Every crate that
    # declares something is read, whether or not it needed the declaration this
    # run, so one whose barrier was reworded or deleted cannot sit there stale.
    for crate, d in sorted(decls.items()):
        for text in d.stale():
            findings.append(
                "%s declares a barrier text that nothing in crate %s waits for any "
                "more: the declaration is stale (a reworded needle, a deleted "
                "barrier, a template that no longer covers it, or a needle the "
                "tree's own producers now account for)" % (text, crate))
    return findings, {
        "needles": len(sites), "tally": tally, "unresolved": unresolved,
        "skipped": skipped, "weak": weak, "wrappers": wrappers,
        "echo_fns": tree.echo_fns, "producers": producers.count,
    }


def report(findings, pop):
    t = pop["tally"]
    declared_n = sum(v for k, v in t.items() if k.startswith("declared:"))
    print("  barrier-needle: %d needle(s) at %d wait fn(s) (%d derived wrapper(s)): "
          "%d plain, %d template, %d declared"
          % (pop["needles"], 1 + len(pop["wrappers"]), len(pop["wrappers"]),
             t["plain"], t["template"], declared_n))
    print("  barrier-needle: producers read -- %s"
          % ", ".join("%s %d" % (k, v) for k, v in sorted(pop["producers"].items())))
    print("  barrier-needle: not graded, by rule -- %d forwarding argument(s) (graded "
          "at the wrapper's callers), %d value(s) the test itself sends (%d "
          "send-and-wait fn(s))"
          % (pop["skipped"]["forwarded"], pop["skipped"]["echo"], len(pop["echo_fns"])))
    print("  barrier-needle: %d argument(s) UNREADABLE; %d template needle(s) rest "
          "on fewer than %d literal characters"
          % (len(pop["unresolved"]), len(pop["weak"]), WEAK_BELOW))
    empty = [k for k in ("rust", "c") if pop["producers"][k] == 0]
    if pop["needles"] == 0 or empty:
        print("  FAIL barrier-needle: a population is EMPTY (needles %d, empty "
              "producer classes %s) -- the reader stopped matching, which a green "
              "would hide" % (pop["needles"], empty or "none"), file=sys.stderr)
        return 2
    for u in pop["unresolved"]:
        print("  FAIL %s:%d  `%s(..)` needle expression %r is neither a literal, a "
              "format! template nor an identifier bound to one in this file, so "
              "this gate cannot say what it waits for"
              % (u.path, u.line, u.fn, u.expr[:60]), file=sys.stderr)
    for f in findings:
        print("  FAIL " + f, file=sys.stderr)
    if findings or pop["unresolved"]:
        return 1
    print("  barrier-needle: OK -- every e2e barrier waits on text some producer "
          "in the tree can print, or declares who does")
    return 0


def load_tree():
    rust = [p for p in tracked(["crates"]) if p.endswith(".rs")]
    cpaths = [p for p in tracked(["."]) if p.endswith(C_EXT) and not p.startswith("vendor/")]
    raw_by_path = {rel: views(rel)[0] for rel in rust}
    # A caller of a wrapper need not mention `wait_for_substring`, and a wrapper
    # may forward to another wrapper, so the readable set grows to a fixed point
    # instead of being decided by one grep.
    chosen = {rel for rel, raw in raw_by_path.items() if BASE_WAIT in raw}
    srcs = {rel: Src(rel, raw_by_path[rel]) for rel in chosen}
    while True:
        names = {n for (_c, n) in wait_wrappers(list(srcs.values()))}
        more = {rel for rel, raw in raw_by_path.items()
                if rel not in srcs
                and any(re.search(r"\b%s\s*\(" % re.escape(n), raw) for n in names)}
        if not more:
            break
        for rel in more:
            srcs[rel] = Src(rel, raw_by_path[rel])
    scripts = [p for p in tracked(["scripts"]) if p.endswith(".sh")]
    producers = load_producers(rust, cpaths, ROOT / "vendor/zenoh-pico", scripts)
    return list(srcs.values()), producers, raw_by_path


# ── self test ────────────────────────────────────────────────────────

def _fixture_producers(*literals, kind="rust"):
    p = Producers()
    for text in literals:
        p.add("fx", kind, rust_segments(text) if kind == "rust" else c_segments(text))
    return p


def selftest():
    ok = True

    def expect(label, cond):
        nonlocal ok
        print("  selftest %-66s %s" % (label, "ok" if cond else "FAIL"))
        ok = ok and cond

    # The measured shape this gate exists for, both halves.
    reworded = "plugin '{declared}' stays Declared -- load failed: {why}"
    fixed = "plugin load failed: {why}"
    expect("R2676 needle vs the reworded line is NOT covered",
           _fixture_producers(reworded).cover("plugin load failed") is None)
    expect("R2676 needle vs the repaired line is covered",
           _fixture_producers(fixed).cover("plugin load failed") is not None)
    expect("a needle crossing a placeholder is covered by its template",
           _fixture_producers("peer: face {} UP").cover("peer: face 0 UP") is not None)
    expect("a needle ending inside a value is covered (steps=1)",
           _fixture_producers("SCRIPT COMPLETE steps={}").cover("SCRIPT COMPLETE steps=1")
           is not None)
    # The catch-all that R2676's first instrument was.
    expect("a template with almost no literal text proves nothing",
           _fixture_producers("{}: {}").cover("plugin load failed: boom") is None)
    expect("a value with whitespace is not one token",
           _fixture_producers("wz plugin: {} failed").cover("plugin load failed") is None)
    expect("a needle wholly inside placeholders scores zero",
           coverage("abcdef", ["a prefix of text ", " suffix of text"]) == 0)
    expect("a C template reads %s and %d as placeholders",
           _fixture_producers("seq=%d size=%s", kind="c").cover("seq=3 size=big")
           is not None)
    expect("a needle with no literal run is left to a declaration",
           _fixture_producers("wz accept: listening on {} ({})").cover("(unixpipe)") is None
           and coverage("(unixpipe)", rust_segments("wz accept: listening on {} ({})")) == 2)

    # The fast matcher is the exact one run quickly; they must not disagree.
    cases = [
        ("plugin load failed", rust_segments("plugin '{declared}' stays Declared -- load failed: {x}")),
        ("plugin load failed", rust_segments("plugin load failed: {x}")),
        ("peer: face 0 UP", rust_segments("peer: face {} UP")),
        ("(unixpipe)", rust_segments("wz accept: listening on {} ({})")),
        ("SCRIPT COMPLETE steps=1", rust_segments("SCRIPT COMPLETE steps={}")),
        ("abcdef", ["a prefix of text ", " suffix of text"]),
        ("x:y", rust_segments("{}: {}")),
        ("face 0 UP (peer <anonymous peer>", rust_segments("face {} UP (peer {})")),
    ]
    agree = all(coverage(n, s, sp) == min(coverage_exact(n, s, sp), STRONG)
                for n, s in cases for sp in (False, True))
    expect("the bit-parallel matcher agrees with the exact one on every fixture", agree)
    spaced = rust_segments("face {} UP (peer {})")
    expect("a value with whitespace is covered only where a human declared it",
           coverage("face 0 UP (peer <anonymous peer>", spaced) == 0
           and coverage("face 0 UP (peer <anonymous peer>", spaced, spaces=True) >= 2)

    # cfg(test) text must not make a barrier look produced.
    code = rust_comments.strip_comments(
        'fn real() { log("kept"); }\n#[cfg(test)]\nmod tests { fn t() { '
        'assert!(m.contains("only in a test")); } }\n', blank_literals=True)
    spans = test_spans(code)
    expect("a #[cfg(test)] mod is a span that excludes its literals",
           len(spans) == 1 and "only in a test" not in code[:spans[0][0]])

    # The wrapper derivation reaches a forwarding fn and its callers, and it does
    # not mistake an unrelated `wait` for one.
    text = (
        'fn wait_for_substring(file: &mut File, needle: &str, t: u64) -> Result<(), ()> { Ok(()) }\n'
        'fn wait_for_marker(f: &mut File, needle: &str, b: u64) {\n'
        '    let _ = wait_for_substring(f, needle, b);\n}\n'
        'fn a_test() {\n    wait_for_marker(&mut f, "never printed", 5);\n'
        '    child.wait();\n    let tail = format!("seq={n} ok");\n'
        '    wait_for_substring(&mut f, &tail, 5);\n}\n')
    src = Src("crates/c/tests/t.rs", text)
    wr = wait_wrappers([src])
    expect("a fn forwarding its needle parameter is derived as a wrapper",
           wr == {("c", "wait_for_marker"): (1, 3)})
    sites, unresolved, skipped = find_needles([src])
    expect("callers' literals and let-bound templates are needles",
           sorted(t for _s, t, _k in sites) == [" ok", "never printed", "seq="])
    expect("the forwarding call is skipped and nothing is unreadable",
           skipped["forwarded"] == 1 and not unresolved)
    src2 = Src("crates/c/tests/u.rs", text.replace('"never printed"', "mystery(1)"))
    _s, unres2, _f = find_needles([src2])
    expect("an argument the reader cannot parse is reported, not dropped",
           len(unres2) == 1)

    # A value the test sends is not producer text, and a barrier on a `let`
    # binding is graded against the binding in ITS function, not a namesake.
    echo = Src("crates/c/tests/e.rs", (
        'fn wait_for_substring(file: &mut File, needle: &str, t: u64) {}\n'
        'fn send_and_wait(z: &str, payload: &str) {\n'
        '    Command::new(z).args(["-v", payload]).spawn();\n'
        '    wait_for_substring(&mut f, payload, 5);\n}\n'
        'fn t1() { send_and_wait("z", "PAYLOAD-A"); }\n'
        'fn t2() {\n    let marker = "wz says this";\n'
        '    wait_for_substring(&mut f, marker, 5);\n}\n'
        'fn t3() {\n    let marker = "a different line";\n'
        '    wait_for_substring(&mut f, marker, 5);\n}\n'))
    tree = Tree([echo])
    esites, eunres, eskipped = tree.needle_sites()
    expect("a send-and-wait fn is an echo fn, not a wrapper",
           ("c", "send_and_wait") in tree.echo_fns and not tree.wrappers)
    expect("its callers' values are skipped as test-sent",
           eskipped["echo"] >= 2 and not eunres)
    expect("a let binding resolves to its own function's value only",
           sorted(t for _s, t, _k in esites) == ["a different line", "wz says this"])
    findings, pop = grade([src], _fixture_producers("something else entirely"),
                          {src.path: ""})
    expect("an uncovered needle is a finding", len(findings) == 3)

    # A declaration binds to its needle exactly.
    body = "fn x() { spawn(zenohd_binary()); wait_for_substring(f, \"ZID:\", t); }\n"
    head = '// barrier-origin: zenohd "ZID:"'
    d = Declarations({"a.rs": head + " -- `a/b.rs` @ `Using ZID:`\n"})
    expect("a matching origin declaration is accepted and counted as used",
           d.origin("ZID:", body) == "zenohd" and not d.stale())
    d = Declarations({"a.rs": head + "\n"})
    expect("a declaration for a reworded needle is not accepted",
           d.origin("ZID: ", body) is None and len(d.stale()) == 1)
    d = Declarations({"a.rs": head + "\n"})
    expect("a foreign kind the barrier's own file never names is not accepted",
           d.origin("ZID:", "fn x() {}\n") is None)
    d = Declarations({"lib.rs": head + "\n"})
    expect("a declaration in another file of the crate covers a barrier here",
           d.origin("ZID:", body) == "zenohd")
    d = Declarations({"a.rs": head + " -- `a/b.rs` @ `unrelated text`\n"})
    expect("a citation sharing no text with the needle is not accepted",
           d.origin("ZID:", body) is None)
    pd = {"a.rs": '// barrier-producer: crates/x/src/a.rs @ "listening on {} ({})" '
                   'for "(unixpipe)"\n'}
    fake = lambda path: ['wz accept: listening on {} ({})']  # noqa: E731
    d = Declarations(pd)
    expect("a producer declaration the template covers is accepted",
           d.producer("(unixpipe)", fake) and not d.stale())
    d = Declarations(pd)
    expect("a producer declaration is bound to ITS needle, not any it could cover",
           not d.producer("Listener added: tcp/127.0.0.1:", fake) and len(d.stale()) == 1)
    d = Declarations({"a.rs": '// barrier-producer: crates/x/src/a.rs @ "listening on {} '
                              '({})" for "(unixsock) x y"\n'})
    expect("a declaration whose template no longer covers its needle is stale",
           not d.producer("(unixsock) x y", lambda p: ["listening on {} ({})x"])
           and len(d.stale()) == 1)
    d = Declarations(pd)
    expect("a producer file that lacks the template is not accepted",
           not d.producer("(unixpipe)", lambda p: ["reworded {}"]))
    # A declaration with no barrier behind it fails the whole gate.
    stale_text = ('// barrier-origin: zenohd "Gone:"\nfn wait_for_substring(file: &mut File, '
                  'needle: &str, t: u64) {}\nfn t() { wait_for_substring(&mut f, "kept", 1); }\n')
    stale_src = Src("crates/c/tests/s.rs", stale_text)
    findings, _pop = grade([stale_src], _fixture_producers("a kept line"),
                           {stale_src.path: stale_text})
    expect("a stale declaration is a finding even when every needle is covered",
           len(findings) == 1 and "stale" in findings[0])
    rc = report([], {"needles": 0, "tally": Counter(), "unresolved": [],
                     "skipped": Counter(), "weak": [], "wrappers": {}, "echo_fns": {},
                     "producers": Counter()})
    expect("an empty population is exit 2, not green", rc == 2)
    return 0 if ok else 1


def main(argv):
    if len(argv) != 2 or argv[1] not in ("--check", "--selftest"):
        print("usage: barrier_needle_gate.py --check | --selftest", file=sys.stderr)
        return 2
    if argv[1] == "--selftest":
        return selftest()
    srcs, producers, raw_by_path = load_tree()
    findings, pop = grade(srcs, producers, raw_by_path)
    return report(findings, pop)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
