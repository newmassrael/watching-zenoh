#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y889 (debt-build-evidence) — a BUILD this repo's CI runs must not have
its output thrown away.

## The failure this ends

Hosted run 32314626012 went red on Layer Qz with one line:

    Qz build deploy/zephyr-app (west) FAIL

and nothing else, in zero seconds. The `west build` behind it was written
`>/dev/null 2>&1`, so the log held the verdict and none of the evidence. There
was no way to tell a missing toolchain from a broken CMakeLists from a
compile error without provisioning Zephyr by hand and running it again — which
is a whole round spent reproducing something the failing run already knew.

Measured across `run-ci.sh` when this was written: THREE builds discarded their
output. The Zephyr one above, the `sce-codegen` rebuild inside Layer B (four
words on failure), and the xtask build inside Layer B2 — that last one worse
than the others in its way, because it SKIPS rather than fails and prints
"libxml2/sce-build toolchain absent?" as a diagnosis when it is a guess. A real
break in the xtask read exactly like a box without libxml2.

R311y756 had already fixed a fourth site, in the same file, for the same
reason. Four is not a habit anybody is going to remember; it is a rule that
needed a gate.

## What it checks

A command that runs a BUILD must not send both streams to `/dev/null`. Redirect
to a file under the run's own log directory and print the evidence on the
failure path, which is what all three repaired sites now do.

## Which files, and which spellings are a build (R4500, open-debt items 369, 372)

The gate first read one file, `run-ci.sh`, and five spellings (`west build`,
`cargo build/test/run`, `scripts/build-*.sh`, `cmake --build`, `make`), and
reported green over everything else as if it had understood it. Both halves
were narrower than the class. MEASURED when they were widened:
`reduced-features-gate.sh`, which the push hook runs, sent a `cargo clippy` to
`/dev/null` and printed "does not build clean" with nothing under it;
`domain-bundles-gate.sh` did the same with `cargo check`; and `run-ci.sh`'s
Layer B sent `verify-codegen.sh`, a wrapper that drives sce-codegen and a
cargo test, to `/dev/null` on the branch that never re-runs it.

The FILES are every tracked shell script and every hook, from `git ls-files`
on each run, so a new script is read the round it lands. The SPELLINGS are the
build tools the tree runs (`cargo` build/test/run/check/clippy/doc/nextest and
a `cargo "${args[@]}"` whose subcommand is in an array, `west` with any
subcommand, `cmake --build`, `make`, `ninja`, a remote `bx ... --`) plus every
tracked script that itself runs one. That last set is DERIVED, not listed: a
script whose own lines run a build is a build wrapper, and so is one that runs
a wrapper, to a fixed point; a wrapper named in no list is the hole a list
would leave. A `--version` / `--help` probe and a `command -v` are not builds.

Lines are LOGICAL: a trailing backslash, and a trailing `|`, `&&` or `||`,
join the next line, which is how bash itself reads them.

## The third arm: a TAIL is not evidence (R4500, open-debt item 370)

A failure path that prints `tail -40 "$log"` shows the cause only when the
cause is in the last forty lines; a compiler error followed by a page of
warnings puts it above the window, and the dump then reads like a failure with
no cause. So a `tail` of what a build wrote -- a file a build line in the same
script redirects into (`>`, `2>`, `&>`, `tee`), or a variable a build's output
was captured into (`out="$(cargo ...)"`) -- is refused. The failure path
sources `scripts/lib/build-evidence.sh` and calls `wz_build_evidence`, which
prints the first lines carrying an error marker and then the tail. The match
is per script, not per function: a generic name (`log`, `out`) captured from a
build anywhere in a script makes every tail of it in that script a build dump,
which errs toward asking for evidence where a tail would have done.

## The second spelling: a build piped into `grep -q`

The same defect written another way. `cargo test ... 2>&1 | grep -qE '^test
result: ok. N passed'` throws the stream away too: `grep -q` keeps nothing, so
a red prints no test output, and under `set -o pipefail` the reader's early
exit races its upstream's SIGPIPE into a false red. `_runci_guarded_test` was
written to end this and says so in its own doc; R2074 converted "the LAST" of
the bare form. It was not the last. Measured when this spelling was added: 18
`cargo test` calls across six layer functions (C1t, C1aa, C1ac, C1aj, C1al,
C1w) still carried it, and a hosted red in C1aa printed `104 passed` from its
one unpiped step and then nothing, so the failing test had to be read out of a
different lane's log. A population counted by hand and declared complete had
leaked the class twice; this is the gate.

R3191 (item 858) closed the exemption this gate first carried for a `tee` placed
between the build and the reader. The `tee` kept the evidence, which is what the
exemption rested on, but not the other half of the defect: the reader still
leaves at its first match, the `tee` takes the SIGPIPE on its next write, and
`pipefail` reports it. A shell miniature of it exits 141 on a run whose summary
matched. 39 call sites in 14 layers carried the shape and were moved to
`_runci_guarded_test`, which captures instead of racing; the gate now holds the
population at zero without an exemption.

It reads LOGICAL lines (a trailing backslash joins the next one, so a pipe on the
line after the build still counts), splits each on `&&`, `||` and `;`, and flags a
segment that holds a build AND a lone `|` into `grep -q`. A comment is not a
command. Its detector is run on a fixture before it is run on the file.

## What it deliberately does NOT check

Every other `>/dev/null 2>&1` in the file, of which there are ~55. Almost all
are `command -v` probes or the gates' own selftests, which run a script with
deliberately bad input and legitimately care about nothing but the exit status.
A rule that flagged those would need an exemption table longer than the
findings, and a table nobody maintains is worse than no gate — the population
here is small BECAUSE the rule is narrow, and that is the design.

A message is not a command: a segment that is an `echo` / `printf`, or a plain
assignment, with no command substitution in it, is not read for a build, so
the word "make" in an error message neither flags its line nor turns its
script into a build wrapper. A redirect on the closing line of a multi-line
subshell (`( ... cargo build ... ) >"$log"` over three lines) is not tied to the
build inside it; the tree's failure dumps of that shape were read by hand when
the third arm was written and none of them tails such a file.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The population: every tracked shell script, and the hooks, which carry no
#: suffix. Asked of `git ls-files` on every run.
PATHSPECS = ("*.sh", ".githooks/*")

#: The build tools, spelled as commands. `cargo` with a subcommand that
#: compiles (or with its subcommand in an array, `cargo "${args[@]}"`), `west`
#: with any subcommand, `cmake --build`, `make` and `ninja` in command position,
#: a `scripts/build-*.sh` however its path is spelled, and a remote `bx ... --`.
BUILD = re.compile(
    r"\bwest\"?\s+(?!-)[a-z][a-z-]*"
    r"|\bcargo\s+(?:\+\S+\s+)?(?:build|test|run|check|clippy|doc|nextest)\b"
    r"|\bcargo\s+\"\$\{?[A-Za-z_][A-Za-z0-9_]*\[@\]\}?\""
    r"|\bscripts/build-[a-z-]+\.sh\b"
    r"|\bcmake\s+--build"
    r"|(?:^|[\s;&|(])(?:make|ninja)(?=\s|$)"
    r"|(?:^|[\s;&|(/])bx\s+(?:[^|;&]*\s)?--(?=\s|$)"
)
#: A segment that only asks whether a tool is there, or what version it is.
PROBE = re.compile(r"--version\b|--help\b|\bcommand\s+-v\b")
#: A segment that only says something, or only sets a variable to one word (an
#: environment prefix before a command, `X=1 cargo test`, is a command).
MESSAGE = re.compile(
    r"^\s*(?:(?:then|else|do|!)\s+)*(?:echo|printf)\b"
    r"|^\s*(?:local\s+|export\s+|readonly\s+)?[A-Za-z_][A-Za-z0-9_]*="
    r"(?:\"[^\"]*\"|'[^']*'|[^\s\"'()]*)\s*$"
)
#: Running a script by path, not sourcing it.
SOURCED_BEFORE = re.compile(r"(?:^|[\s;&|(])(?:source|\.)\s+\"?[^\s\"]*$")

DISCARD = re.compile(r">\s*/dev/null\s+2>&1|2>&1\s*>\s*/dev/null|&>\s*/dev/null")

# `| grep -q`, `| grep -qE`, `| grep -Eq`: a pipe whose reader keeps nothing. A
# lone `|` only: `||` is split away before this is looked for.
PIPED_GREP_Q = re.compile(r"\|\s*grep\s+-[A-Za-z]*q")

#: A file a command writes: `>`, `>>`, `2>`, `&>`, and `tee [-a]`. `>&2` and
#: `2>&1` duplicate a stream and name no file.
_WORD = r"(\"[^\"]*\"|'[^']*'|[^\s;&|()<>]+)"
REDIRECT = re.compile(r"(?:^|[^<>&0-9])(?:[0-9]|&)?>>?\s*(?!&)" + _WORD)
TEE = re.compile(r"\btee\s+(?:-a\s+)?" + _WORD)
#: A variable a command's output is captured into: `out=$(...)`, `out="$(...)"`.
CAPTURE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)=\"?\$\(")
#: `tail` and the words after it up to the end of its command.
TAIL_ARGS = re.compile(r"\btail\b([^|;&<>]*)")
#: A variable's text handed to `tail`: piped from `printf`/`echo`/`cat`, or as a
#: here-string.
TAIL_PIPED = re.compile(
    r"(?:\bprintf\s+(?:'[^']*'|\"[^\"]*\")|\becho(?:\s+-[neE]+)?|\bcat)\s+"
    r"\"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?\"?\s*\|\s*tail\b"
)
TAIL_HERE = re.compile(r"\btail\b[^|;&]*<<<\s*\"?\$\{?([A-Za-z_][A-Za-z0-9_]*)")


def logical_lines(lines: list[str]) -> list[tuple[int, str]]:
    """`(first physical line, text)` with continuations joined, so a pipe on
    the line after the build is still the build's pipe.

    A line continues when it ends in `\\`, `|`, `&&` or `||`, which is where
    bash itself keeps reading. A comment line never continues: a table row in a
    comment that ends in `|` would otherwise swallow the command after it."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 0
    for i, line in enumerate(lines):
        if not buf:
            start = i
        stripped = line.rstrip()
        if not stripped.lstrip().startswith("#"):
            if stripped.endswith("\\"):
                buf.append(stripped[:-1])
                continue
            if stripped.endswith("|") or stripped.endswith("&&"):
                buf.append(stripped)
                continue
        buf.append(line)
        out.append((start, " ".join(buf)))
        buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


def commands(lines: list[str]) -> list[tuple[int, str]]:
    """The logical lines that are not comments."""
    return [(at, t) for at, t in logical_lines(lines) if not t.lstrip().startswith("#")]


def segments(text: str) -> list[str]:
    """One command list split on `&&`, `||` and `;`."""
    return re.split(r"&&|\|\||;", text)


def wrapper_pattern(wrappers: set[str]) -> re.Pattern[str] | None:
    """A run of any of `wrappers` (tracked paths), however its path is rooted."""
    if not wrappers:
        return None
    names = "|".join(re.escape(w) for w in sorted(wrappers))
    return re.compile(r"(?<![A-Za-z0-9_.-])(?:" + names + r")(?![A-Za-z0-9_.-])")


def is_build(segment: str, wrappers: re.Pattern[str] | None) -> re.Match[str] | None:
    """The build this segment runs, or None.

    A probe, a message and a literal assignment run none; a wrapper that is
    sourced defines functions and runs none either."""
    if PROBE.search(segment) or (MESSAGE.search(segment) and "$(" not in segment):
        return None
    found = BUILD.search(segment)
    if found:
        return found
    if wrappers is not None:
        for m in wrappers.finditer(segment):
            if not SOURCED_BEFORE.search(segment[: m.start()]):
                return m
    return None


def derive_wrappers(texts: dict[str, list[str]]) -> set[str]:
    """The tracked scripts that run a build, to a fixed point.

    A script is a build wrapper when one of its own commands is a build, or
    runs a script already known to be one. Only `*.sh` files can be run by
    path; a hook is never invoked by another script."""
    cmds = {
        path: [seg for _, t in commands(lines) for seg in segments(t)]
        for path, lines in texts.items()
        if path.endswith(".sh")
    }
    wrappers: set[str] = set()
    changed = True
    while changed:
        changed = False
        pattern = wrapper_pattern(wrappers)
        for path, segs in cmds.items():
            if path in wrappers:
                continue
            if any(is_build(seg, pattern) for seg in segs):
                wrappers.add(path)
                changed = True
    return wrappers


def _unquote(word: str) -> str:
    return word.strip("\"'")


def build_outputs(lines: list[str], wrappers: re.Pattern[str] | None) -> tuple[set[str], set[str]]:
    """`(files, variables)` a build in this script writes its output into.

    Read off a whole logical line that holds a build, so a redirect after a
    `$( ... )` or after the closing `)` of a one-line subshell is the build's."""
    files: set[str] = set()
    variables: set[str] = set()
    for _, text in commands(lines):
        if not any(is_build(seg, wrappers) for seg in segments(text)):
            continue
        for m in REDIRECT.finditer(text):
            word = _unquote(m.group(1))
            if word and word != "/dev/null":
                files.add(word)
        for m in TEE.finditer(text):
            files.add(_unquote(m.group(1)))
        for m in CAPTURE.finditer(text):
            variables.add(m.group(1))
    return files, variables


def tail_dumps(lines: list[str], wrappers: re.Pattern[str] | None) -> list[tuple[int, str]]:
    """The `tail`s of what a build in this script wrote.

    A tail shows the cause only when the cause is inside its window, so a
    failure path prints `wz_build_evidence` (scripts/lib/build-evidence.sh),
    which prints the first error lines as well."""
    files, variables = build_outputs(lines, wrappers)
    found: list[tuple[int, str]] = []
    for at, text in commands(lines):
        for segment in segments(text):
            read: set[str] = set()
            for m in TAIL_ARGS.finditer(segment):
                for word in m.group(1).split():
                    read.add(_unquote(word))
            hit = bool(read & files)
            for m in TAIL_PIPED.finditer(segment):
                hit = hit or m.group(1) in variables
            for m in TAIL_HERE.finditer(segment):
                hit = hit or m.group(1) in variables
            if hit:
                found.append((at, segment.strip()))
    return found


def discarded_builds(lines: list[str], wrappers: re.Pattern[str] | None) -> list[tuple[int, str]]:
    """The builds that send both streams to /dev/null."""
    found: list[tuple[int, str]] = []
    for at, text in commands(lines):
        for segment in segments(text):
            if DISCARD.search(segment) and is_build(segment, wrappers):
                found.append((at, segment.strip()))
    return found


def piped_builds(lines: list[str], wrappers: re.Pattern[str] | None = None) -> list[tuple[int, str]]:
    """The BUILDs whose output is piped into `grep -q`.

    The reader stops at its first match and keeps nothing, so a red carries no
    evidence, and under `set -o pipefail` its upstream races a SIGPIPE against
    that early exit. A command list is split on `&&`, `||` and `;` first, so
    only a pipe INSIDE one command counts, and a comment is not a command.

    R3191 (open-debt item 858) — A `tee` BETWEEN THE BUILD AND THE READER IS NO
    LONGER AN EXEMPTION. It keeps the stream, so that shape does not lose the
    evidence, which is why it was exempt; but the reader is still `grep -q`,
    which leaves at its first match, and the `tee` then takes the SIGPIPE on its
    next write. Under `set -o pipefail` that is the pipeline's status, so a run
    whose tests all PASSED goes red whenever the build prints anything after the
    summary line it matched (a lib crate's `Doc-tests` section, a second test
    binary, a trailing warning). Reproduced in miniature: a producer printing
    the matching line, then 0.3s later two more lines, through `tee | grep -q`
    under pipefail, exits 141. The race is the same defect as the evidence-less
    shape and shares its remedy, so it shares its gate: the exemption was a
    claim that the risk was "a different defect with its own count", and the
    count was 39 call sites in 14 layers.
    """
    found: list[tuple[int, str]] = []
    for at, text in commands(lines):
        for segment in segments(text):
            build = is_build(segment, wrappers)
            reader = PIPED_GREP_Q.search(segment)
            if not build or not reader or reader.start() < build.start():
                continue
            found.append((at, segment.strip()))
    return found


def _lines(text: str) -> list[str]:
    return text.split("\n")


def selftest_spellings() -> None:
    """Every build spelling is seen discarding its output, and a probe, a
    message and a comment are not builds."""
    flagged = [
        '    if cargo check -p wz --features "$b" >/dev/null 2>&1; then',
        '    if ! cargo "${args[@]}" -- -D warnings >/dev/null 2>&1; then',
        "    cargo +nightly clippy -p x &>/dev/null",
        "    ninja -C build >/dev/null 2>&1 || fail=1",
        '    "$VENV/bin/west" update >/dev/null 2>&1',
        "    bx --host pc2 -- ./run.sh &>/dev/null",
        '    "$ROOT/scripts/build-zenohd.sh" >/dev/null 2>&1',
        "    make -C deploy all 2>&1 >/dev/null",
        "    cargo build --release \\\n        >/dev/null 2>&1",
        "    cargo build --release &&\n        cargo test -p x >/dev/null 2>&1",
        # A comment ending in `|` does not swallow the command after it.
        "    # | a | b |\n    cargo build >/dev/null 2>&1",
    ]
    clean = [
        '    "$VENV/bin/west" --version >/dev/null 2>&1',
        "    command -v ninja >/dev/null 2>&1",
        '    echo "never make a build quiet" >/dev/null 2>&1',
        '    then echo "cargo build failed" >/dev/null 2>&1',
        "    # cargo build >/dev/null 2>&1",
        '    if ! cargo build >"$log" 2>&1; then',
        "    cargo metadata --no-deps >/dev/null 2>&1",
    ]
    for text in flagged:
        assert discarded_builds(_lines(text), None), f"selftest: not flagged: {text!r}"
    for text in clean:
        assert not discarded_builds(_lines(text), None), f"selftest: flagged: {text!r}"


def selftest_wrappers() -> None:
    """A script that runs a build is a build, through any number of scripts,
    and a sourced library, a message and a hook are not."""
    texts = {
        "scripts/a.sh": ["cargo build -p x"],
        "scripts/b.sh": ['bash "$ROOT/scripts/a.sh" "$@"'],
        "scripts/lib/d.sh": ["bash scripts/b.sh --all"],
        "scripts/c.sh": ['echo "make sure the build ran"', "source scripts/lib/d.sh"],
        "scripts/e.sh": ['. "$ROOT/scripts/a.sh"', 'NOTE="make it so"'],
        ".githooks/pre-push": ["bash scripts/a.sh"],
    }
    got = derive_wrappers(texts)
    want = {"scripts/a.sh", "scripts/b.sh", "scripts/lib/d.sh"}
    assert got == want, f"selftest: wrappers {sorted(got)} != {sorted(want)}"
    pattern = wrapper_pattern(got)
    assert discarded_builds(["    bash scripts/lib/d.sh >/dev/null 2>&1"], pattern), (
        "selftest: a derived wrapper discarding its output was not flagged"
    )
    assert not discarded_builds(["    bash scripts/c.sh >/dev/null 2>&1"], pattern), (
        "selftest: a script that runs no build was flagged"
    )
    assert not discarded_builds(["    bash scripts/lib/d.sh >/dev/null 2>&1"], None), (
        "selftest: the wrapper arm fired with no wrapper set"
    )


def selftest_helper() -> None:
    """The remedy the third arm names shows a cause a tail would not.

    A synthetic build log puts its error above a three-line window. The window
    alone (the control) must miss it, and `wz_build_evidence` with the same
    window must print it; a helper that printed only the tail would pass the
    lint and fail here."""
    log = "\n".join(
        ["   Compiling x v0.1.0", "error[E0425]: cannot find value `y` in this scope"]
        + [f"warning: unused import {i}" for i in range(8)]
        + ["error: could not compile `x` (lib) due to 1 previous error"]
    )
    helper = ROOT / "scripts" / "lib" / "build-evidence.sh"
    control = subprocess.run(
        ["tail", "-n", "3"], input=log, capture_output=True, text=True, check=False
    ).stdout
    assert "E0425" not in control, "selftest: the control window already shows the cause"
    shown = subprocess.run(
        ["bash", "-c", 'source "$1" && wz_build_evidence - 3', "_", str(helper)],
        input=log,
        capture_output=True,
        text=True,
        check=False,
    )
    assert shown.returncode == 0, f"selftest: the helper exited {shown.returncode}: {shown.stderr}"
    assert "2:error[E0425]" in shown.stdout, (
        f"selftest: wz_build_evidence did not print the first error line:\n{shown.stdout}"
    )
    assert "could not compile" in shown.stdout, "selftest: the helper dropped the tail"
    quiet = subprocess.run(
        ["bash", "-c", 'source "$1" && wz_build_evidence - 2', "_", str(helper)],
        input="a\nb\n",
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    assert "no line of the build carries an error marker" in quiet, (
        "selftest: a log with no marker must say so rather than print an empty section"
    )


def selftest_tails() -> None:
    """A tail of what a build wrote is refused; the helper, and a tail of
    anything else, are not."""
    flagged = [
        ('if ! cargo build >"$log" 2>&1; then\n    tail -40 "$log" >&2\nfi', 1),
        (
            "out=$(cd crates && cargo test -p x -- --list 2>&1); rc=$?\n"
            "printf '%s\\n' \"$out\" | tail -20 | sed 's/^/  /' >&2",
            1,
        ),
        (
            'cargo test -p x 2>"$tmp/err" | tee "$tmp/all"\n'
            'tail -n 15 "$tmp/err"\n'
            'tail -n 15 "$tmp/all"',
            2,
        ),
        ('out="$(cargo clippy -p x 2>&1)"\ntail -n 5 <<<"$out"', 1),
        ("(cd crates && cargo test -p x) >/tmp/b-$$.log 2>&1\ntail -3 /tmp/b-$$.log", 1),
    ]
    clean = [
        'if ! cargo build >"$log" 2>&1; then\n    wz_build_evidence "$log" 40 >&2\nfi',
        'cargo build >"$log" 2>&1\ntail -n 1 "$HISTORY"',
        "out=$(git status --short)\nprintf '%s' \"$out\" | tail -1",
        'tail -n "$tail_n" "$log"',
        '# cargo build >"$log" 2>&1\ntail -40 "$log"',
    ]
    for text, n in flagged:
        got = tail_dumps(_lines(text), None)
        assert len(got) == n, f"selftest: {len(got)} tail dump(s), want {n}: {text!r}"
    for text in clean:
        assert not tail_dumps(_lines(text), None), f"selftest: flagged: {text!r}"


def selftest() -> None:
    """The detector is checked on a fixture before it is trusted on the file: a
    gate that cannot see the shape it exists for reports a clean surface."""
    selftest_spellings()
    selftest_wrappers()
    selftest_tails()
    selftest_helper()
    flagged = [
        "        && cargo test -p x --quiet 2>&1 | grep -qE '^test result: ok\\. 5 passed' \\",
        "    cargo test -p x --quiet 2>&1 \\\n        | grep -qE '^test result: ok\\. 5 passed'",
        "    cargo test -p x --quiet | grep -q passed",
        # R3191 — a `tee` in between kept the stream and used to be exempt; the
        # reader's early exit still hands the `tee` a SIGPIPE under pipefail.
        "    cargo test -p x --quiet 2>&1 | tee /dev/stderr | grep -qE 'passed'",
        "    cargo test -p x --quiet 2>&1 \\\n        | tee /dev/stderr | grep -qE 'passed'",
        "    WZ_X=\"$y\" cargo test -p x --quiet 2>&1 | tee /dev/stderr | grep -Eq 'passed'",
    ]
    clean = [
        "    _runci_guarded_test C1x 5 cargo test -p x --quiet \\\n        || return 1",
        '    out="$(cd crates && cargo test -p x --quiet 2>&1)" || return 1',
        "    grep -qE '^test result: ok\\. 5 passed' <<<\"$out\" || return 1",
        "    # cargo test -p x 2>&1 | grep -qE 'passed' is the shape this forbids",
        "    cargo test -p x --quiet 2>&1 | tee /dev/stderr",
        "    cargo test -p x --quiet || echo x | grep -q x",
    ]
    for text in flagged:
        assert piped_builds(text.split("\n")), f"selftest: not flagged: {text!r}"
    for text in clean:
        assert not piped_builds(text.split("\n")), f"selftest: flagged: {text!r}"


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        selftest()
        print("build-evidence: selftest ok")
        return 0
    selftest()
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", *PATHSPECS],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if listed.returncode != 0:
        print(
            f"build-evidence: FAIL -- `git ls-files` exited {listed.returncode}, so "
            f"the population of shell scripts is unknown: {listed.stderr.strip()}",
            file=sys.stderr,
        )
        return 1
    texts: dict[str, list[str]] = {}
    for rel in sorted(p for p in listed.stdout.split("\0") if p):
        path = ROOT / rel
        if path.is_file():
            texts[rel] = path.read_text(errors="replace").splitlines()
    wrappers = derive_wrappers(texts)
    pattern = wrapper_pattern(wrappers)

    findings: list[str] = []
    scanned = 0
    for rel, lines in texts.items():
        scanned += len(lines)
        for at, segment in discarded_builds(lines, pattern):
            findings.append(
                f"{rel}:{at + 1}: a BUILD discards both "
                f"streams, so its failure will carry no evidence and reading "
                f"it means running the build again by hand. Redirect to a file "
                f"under ${{RUNCI_LOG_DIR:-crates/target/run-ci-logs}} (or a "
                f"mktemp file) and print `wz_build_evidence` on the failure "
                f"path.\n      {segment[:120]}"
            )
        for at, segment in tail_dumps(lines, pattern):
            findings.append(
                f"{rel}:{at + 1}: a `tail` of what a BUILD wrote is the only "
                f"evidence printed, and a cause above its window reads as no "
                f"cause (item 370). Source scripts/lib/build-evidence.sh and "
                f"print `wz_build_evidence <log> <lines>`, which shows the "
                f"first error lines before the tail.\n      {segment[:120]}"
            )
        for at, segment in piped_builds(lines, pattern):
            findings.append(
                f"{rel}:{at + 1}: a BUILD is piped into "
                f"`grep -q`, which leaves at its first match: without a `tee` a "
                f"red carries no evidence, and with one the `tee` takes the "
                f"SIGPIPE on its next write, which `set -o pipefail` turns into "
                f"a red for a run whose tests all passed (item 858). Run it through "
                f"`_runci_guarded_test <label> <N> cargo test ...`, which streams "
                f"the output and asserts the captured copy.\n      "
                f"{segment[:120]}"
            )

    if not scanned:
        print(
            "build-evidence: FAIL -- read 0 line(s). An empty population is "
            "indistinguishable from total compliance, so it cannot pass.",
            file=sys.stderr,
        )
        return 1

    if findings:
        print("build-evidence: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(
        f"  build-evidence: {len(texts)} script(s), {scanned} line(s) read, "
        f"{len(wrappers)} build wrapper(s) derived; 0 build(s) discarding or "
        f"tail-dumping their own output"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
