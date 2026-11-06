#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4296 (no register item) -- make a script's `--test <name>` of one crate independent of where
the crate keeps the file.

`cargo test -p C --test N` runs the test file `tests/N.rs`. Once `merge_tests.py` has merged the
crate, `N` is a module of an executable and the spelling is `--test <target> files::N::`, which
differs by file and by crate. The script should not hold that, so this rewrites each
`--test N` of a command that names `-p C` into

    wz_test_args C N                       (a line before the command; scripts/lib/test_target.sh)
    cargo test -p C "${WZ_TEST_ARGS[@]}" ...

where `wz_test_args` sets the array to `--test N` while the file is `tests/N.rs` (the command is
the same as before) and to the merged spelling after it. An array, not a command substitution:
the arguments are two words after a merge and an unquoted substitution is what shellcheck refuses
(SC2046). A filter of one test beside `--test N` is the helper's third word. `--verify` reads the
result back: the two forms turned into `--test N [test]` must be the file the rewrite started from.
It changes only what it can prove safe and LISTS the rest for a hand:

  * the name is not a test file of the crate (it names a target of another crate, a variable);
  * the command has a second `--test` or a positional test filter before `--` (cargo takes one
    filter before `--`, and the merged spelling is one);
  * the `--test N` is inside single quotes (the substitution would not run);
  * `--test=N` (the spelling with an equals sign).

    retarget_test_refs.py --crate C [--file scripts/run-ci.sh]            report, change nothing
    retarget_test_refs.py --crate C [--file F] --apply                    write the file
    retarget_test_refs.py --selftest
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
import tempfile
from pathlib import Path

import test_sources

ROOT = Path(__file__).resolve().parents[2]

# cargo's flags that take a value (the value is not a positional filter).
VALUE_FLAGS = {
    "-p", "--package", "--features", "-F", "--test", "--bin", "--bench", "--example", "-j",
    "--jobs", "--target", "--target-dir", "--manifest-path", "--profile", "--color",
    "--message-format", "--exclude", "--timings", "--config", "-Z", "--lockfile-path",
}

TEST_REF = re.compile(r"--test\s+([A-Za-z_][A-Za-z0-9_]*)\b")
TEST_EQ = re.compile(r"--test=([A-Za-z_][A-Za-z0-9_]*)")
PACKAGE = re.compile(r"(?:-p|--package)[ =]+([A-Za-z0-9_-]+)")
ARRAY = '"${WZ_TEST_ARGS[@]}"'
# A command that builds a test target and runs none (clippy, check, build, doc) takes the target
# alone: a filter is `cargo test`'s.
TARGET_ARRAY = '"${WZ_TEST_TARGET[@]}"'
BUILD_ONLY = {"clippy", "check", "build", "doc", "fix", "bench"}
CARGO_SUB = re.compile(r"\bcargo\s+(?:\+\S+\s+)?([a-z][a-z-]*)")
CALL = re.compile(r"(?m)^[ \t]*wz_test_args[ \t]+[A-Za-z0-9_-]+[ \t]+([A-Za-z0-9_]+)(?:[ \t]+([A-Za-z0-9_:]+))?[ \t]*\n")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_:]*")
CHAIN_CALL = re.compile(
    r"^[ \t]*&&[ \t]+wz_test_args[ \t]+[A-Za-z0-9_-]+[ \t]+([A-Za-z0-9_]+)(?:[ \t]+([A-Za-z0-9_:]+))?[ \t]*\\\n")
INLINE_CALL = re.compile(
    r"wz_test_args[ \t]+[A-Za-z0-9_-]+[ \t]+([A-Za-z0-9_]+)(?:[ \t]+([A-Za-z0-9_:]+))?[ \t]*&&[ \t]*")


def logical_commands(lines: list[str]) -> list[tuple[int, int]]:
    """[(first line, last line)] (0-based, inclusive) of each backslash-continued command."""
    spans: list[tuple[int, int]] = []
    start = 0
    for i, line in enumerate(lines):
        if not line.rstrip("\n").rstrip().endswith("\\"):
            spans.append((start, i))
            start = i + 1
    if start < len(lines):
        spans.append((start, len(lines) - 1))
    return spans


def inside_single_quotes(line: str, position: int) -> bool:
    """Whether `position` of `line` is within a single-quoted string (a crude, line-local read)."""
    return line[:position].replace("\\'", "").count("'") % 2 == 1


def positionals(command: str) -> list[str]:
    """The tokens of a `cargo test` command, before `--`, that are filters: not a flag and not a
    flag's value. The helper's own expansion stands for a `--test N` pair."""
    try:
        words = shlex.split(command, comments=False, posix=True)
    except ValueError:
        return ["<unparsed>"]
    try:
        at = words.index("test")
    except ValueError:
        return []
    found: list[str] = []
    skip = False
    for word in words[at + 1:]:
        if skip:
            skip = False
        elif word in ("--", "||", "&&", ";", "|", ")", "&"):
            break
        elif word in VALUE_FLAGS:
            skip = True
        elif word.startswith("-"):
            continue
        elif word.startswith("$") or "=" in word and not word.startswith("--"):
            continue  # a shell expansion or an assignment, not a filter
        else:
            found.append(word)
    return found


def retarget(text: str, crate: str, crate_tests: Path) -> tuple[str, int, list[str]]:
    """(the new text, the number of references rewritten, the lines for a hand)."""
    lines = text.splitlines(keepends=True)
    manual: list[str] = []
    deleted: set[int] = set()
    inserted: dict[int, str] = {}
    done = 0
    for first, last in logical_commands(lines):
        block = lines[first:last + 1]
        command = " ".join(l.rstrip("\n").rstrip("\\") for l in block)
        if "cargo" not in command or "test" not in command:
            continue
        packages = set(PACKAGE.findall(command))
        if crate not in packages:
            continue
        refs = TEST_REF.findall(command)
        if not refs and not TEST_EQ.search(command):
            continue
        subs = CARGO_SUB.findall(command)
        if len(subs) > 1:
            manual.append(f"{first + 1}: {len(subs)} cargo commands in one ({', '.join(subs)})")
            continue
        build_only = bool(subs) and subs[0] in BUILD_ONLY
        located = [n for n in refs if test_sources.locate(crate_tests, n)]
        if TEST_EQ.search(command):
            manual.append(f"{first + 1}: `--test=NAME` spelling")
            continue
        if len(refs) != 1:
            manual.append(f"{first + 1}: {len(refs)} `--test` in one command")
            continue
        if refs[0] not in located:
            manual.append(f"{first + 1}: `--test {refs[0]}` is no test file of {crate}")
            continue
        others = positionals(command)
        within = None
        if build_only and others:
            manual.append(f"{first + 1}: a filter {others} beside `--test {refs[0]}` of a build")
            continue
        if len(others) == 1 and IDENT.fullmatch(others[0]):
            within = others[0]
        elif others:
            manual.append(f"{first + 1}: a filter {others} beside `--test {refs[0]}`")
            continue
        hit = False
        for i in range(first, last + 1):
            m = TEST_REF.search(lines[i])
            if not m:
                continue
            if inside_single_quotes(lines[i], m.start()):
                manual.append(f"{i + 1}: `--test {m.group(1)}` inside single quotes")
                break
            args = f"{crate} {m.group(1)}" + (f" {within}" if within else "")
            call = TARGET_ARRAY if build_only else ARRAY
            lines[i] = lines[i][:m.start()] + call + lines[i][m.end():]
            indent = re.match(r"\s*", lines[first]).group(0)
            inserted[first] = inserted.get(first, "") + f"{indent}wz_test_args {args}\n"
            hit = True
            done += 1
            if within:
                # The filter now rides in the helper: remove its own token, after the call.
                tail_from = m.start() + len(call)
                for j in range(i, last + 1):
                    start = tail_from if j == i else 0
                    word = re.search(rf"(?<![\w$.-]){re.escape(within)}(?![\w])", lines[j][start:])
                    if not word:
                        continue
                    a, b = start + word.start(), start + word.end()
                    rest = (lines[j][:a] + lines[j][b:]).strip().rstrip("\\").strip()
                    if not rest:
                        deleted.add(j)
                    else:
                        lines[j] = (lines[j][:a].rstrip(" ") + " " + lines[j][b:].lstrip(" ")
                                    if lines[j][b:].strip() else lines[j][:a].rstrip(" ") + "\n")
                    break
            break
        if not hit and not any("single quotes" in x for x in manual[-1:]):
            manual.append(f"{first + 1}: `--test {refs[0]}` split across lines")
    out: list[str] = []
    for k, line in enumerate(lines):
        if k in inserted:
            out.append(inserted[k])
        if k not in deleted:
            out.append(line)
    return "".join(out), done, manual


def expand(text: str, keep_lines: bool = False) -> str:
    """`text` with each `wz_test_args C N [W]` line and the next `"${WZ_TEST_ARGS[@]}"` turned
    back into `--test N [W]`: the file as it read before the rewrite, up to line breaks.

    A lint that reports `file:line` reads it with `keep_lines`: a call line is left as an empty
    line, so every other line keeps the number it has in the file."""
    out: list[str] = []
    pending: tuple[str, str] | None = None  # (what ARRAY stands for, what TARGET_ARRAY stands for)
    for line in text.splitlines(keepends=True):
        # A call on a line of its own inside a chain of commands:
        #     && wz_test_args C N [W] \
        #     && cargo ...
        # The `&&` of the next line is the one the command always had.
        chain = CHAIN_CALL.match(line)
        if chain:
            target = f"--test {chain.group(1)}"
            pending = (target + (f" {chain.group(2)}" if chain.group(2) else ""), target)
            if keep_lines:
                out.append("\\\n")
            continue
        # A call inside a chain of commands: `... && wz_test_args C N [W] && cargo ...`.
        inline = INLINE_CALL.search(line)
        if inline:
            target = f"--test {inline.group(1)}"
            pending = (target + (f" {inline.group(2)}" if inline.group(2) else ""), target)
            line = line[:inline.start()] + line[inline.end():]
        m = CALL.match(line)
        if m:
            target = f"--test {m.group(1)}"
            pending = (target + (f" {m.group(2)}" if m.group(2) else ""), target)
            if keep_lines:
                out.append("\n")
            continue
        if pending is not None:
            for token, stands_for in zip((ARRAY, TARGET_ARRAY), pending):
                if token in line:
                    line = line.replace(token, stands_for, 1)
                    pending = None
                    break
        # `--exact "${WZ_TEST_PREFIX}<test>"` names the test inside its file's module in a merged
        # executable; read back as the `--exact <test>` it was before the merge.
        line = line.replace("${WZ_TEST_PREFIX}", "")
        out.append(line)
    return "".join(out)


def tokens(text: str) -> list[str]:
    return [t for t in text.replace("\\\n", " ").split() if t != "\\"]


def verify(current: str, before: str) -> tuple[bool, str]:
    """Whether `current`, expanded, has the same words as `before`; the first difference if not."""
    # `before` is expanded too: it may already hold the calls of an earlier crate's rewrite.
    a, b = tokens(expand(current)), tokens(expand(before))
    if a == b:
        return True, f"{len(a)} words, all the same"
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return False, f"word {i}: {x!r} against {y!r} (…{' '.join(b[max(0, i - 4):i])})"
    return False, f"{len(a)} words against {len(b)}"


def selftest() -> int:
    failures = 0

    def check(label: str, ok: bool) -> None:
        nonlocal failures
        if not ok:
            failures += 1
            print(f"retarget selftest FAIL: {label}")

    with tempfile.TemporaryDirectory() as tmp:
        tests = Path(tmp) / "tests"
        tests.mkdir()
        (tests / "alpha.rs").write_text("")
        (tests / "beta.rs").write_text("")
        text = (
            "    cargo test -p wz-c --test alpha --quiet \\\n"
            "        -- --ignored\n"
            "    cargo test -p wz-c \\\n"
            "        --test beta -- --nocapture\n"
            "    cargo test -p wz-other --test alpha\n"
            "    cargo test -p wz-c --test alpha some_filter\n"
            "    cargo test -p wz-c --test alpha --test beta\n"
            "    cargo test -p wz-c --test gamma\n"
            "    sh -c 'cargo test -p wz-c --test alpha'\n"
            "    cargo test -p wz-c --target-dir out --test alpha -- x\n"
            "    echo done\n"
        )
        out, done, manual = retarget(text, "wz-c", tests)
        check("four rewritten references", done == 4)
        check("each one has its call before it",
              "    wz_test_args wz-c alpha\n    cargo test -p wz-c "
              + ARRAY + " --quiet \\\n" in out)
        check("a multi-line command is rewritten",
              "    wz_test_args wz-c beta\n    cargo test -p wz-c \\\n        " + ARRAY in out)
        check("another crate is not touched", "cargo test -p wz-other --test alpha" in out)
        check("a one-word filter rides in the call",
              "wz_test_args wz-c alpha some_filter\n" in out and out.count("some_filter") == 1)
        spread = ("    cargo test -p wz-c \\\n        --test alpha \\\n        one_test \\\n"
                  "        -- --ignored\n    cargo test -p wz-c --test alpha a b\n")
        out2, done2, manual2 = retarget(spread, "wz-c", tests)
        check("a filter alone on its line leaves no empty line",
              out2.splitlines()[:4] == ["    wz_test_args wz-c alpha one_test",
                                        "    cargo test -p wz-c \\",
                                        "        " + ARRAY + " \\",
                                        "        -- --ignored"] and done2 == 1)
        check("two filters are listed", any("['a', 'b']" in m for m in manual2))
        check("two --test are listed", any("2 `--test`" in m for m in manual))
        check("a non-file is listed", any("gamma" in m for m in manual))
        check("single quotes are listed", any("single quotes" in m for m in manual))
        check("a flag's value is no filter", ARRAY + " -- x" in out)
        again, more, _ = retarget(out, "wz-c", tests)
        check("a second run changes nothing", more == 0 and again == out)
        ok, why = verify(out, text)
        check(f"expanded, the rewrite reads as the file it began from ({why})", ok)
        ok2, _ = verify(out2, spread)
        check("a filter on its own line verifies too", ok2)
        check("a changed file does not verify", not verify(out + "echo x\n", text)[0])
    if failures == 0:
        print("retarget_test_refs: selftest OK")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--crate")
    ap.add_argument("--file", default="scripts/run-ci.sh")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--verify", metavar="BEFORE",
                    help="the file as it read before the rewrite: read the result back against it")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.verify:
        ok, why = verify((ROOT / args.file).read_text(), Path(args.verify).read_text())
        print(f"{args.file}: {'VERIFIED' if ok else 'DIFFERENT'} -- {why}")
        return 0 if ok else 1
    if not args.crate:
        ap.error("--crate is required")
    path = ROOT / args.file
    text = path.read_text()
    new, done, manual = retarget(text, args.crate, ROOT / "crates" / args.crate / "tests")
    print(f"{args.file}: {done} reference(s) of {args.crate} "
          f"{'rewritten' if args.apply else 'to rewrite'}, {len(manual)} for a hand")
    for line in manual:
        print(f"  by hand  {line}")
    if args.apply and new != text:
        path.write_text(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
