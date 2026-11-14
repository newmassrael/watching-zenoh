#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""A ledger round written down as DATA, so it can travel in a commit.

R4392 (no register item) -- the descriptor a queue integrator files a round from.

An author writes a round's prose in four files outside the repository, and its number
is the store's last round plus one on the tree it lands on. A commit can carry neither,
so a queue integrator, which cherry-picks a commit onto the remote tip, would have
nowhere to read a round from. A descriptor is the same round as one tracked file: the
prose, the impact ids and no number. The number is the one fact the commit cannot
know, so it is not in the descriptor and `scripts/file-round.sh` computes it on the
candidate. `scripts/land.sh` writes the descriptor from `append-round.sh`'s own
arguments (`write`), so the author's files become data before the commit leaves.

    docs/rounds/pending/<slug>.toml

    impact       = ["<store section id>", ...]     # list_sections ids, as --impact takes
    decision     = '''...'''
    changes      = '''...'''
    verification = '''...'''
    carry        = '''...'''

Exactly these five keys. An unknown key is refused because a typo would otherwise
file a round with a field silently missing; a missing or empty key is refused because
`append-round.sh` refuses an entry with no prose.

    round_descriptor.py emit <descriptor> <outdir>   write decision.txt, changes.txt,
                                                     verification.txt, carry.txt into
                                                     <outdir>; print the impact ids,
                                                     comma separated, on stdout
    round_descriptor.py write <descriptor> <args>    write a new descriptor from
                                                     append-round.sh's arguments:
                                                     --decision-file, --changes-file,
                                                     --verification-file, --carry-file
                                                     and --impact, each once (`--x v` or
                                                     `--x=v`); any other is refused
    round_descriptor.py --selftest                   every refusal and the happy path

A written descriptor is read back by the same reader `emit` uses and compared with
what was given; one that does not read back as written is removed and refused, so
`write` never leaves a file `file-round.sh` would file differently.

Exit 0 ok; 1 the descriptor is not a round; 2 usage.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

# The repository's reader of TOML for the floor interpreter: `tomllib` is stdlib only from 3.11,
# and the hosted floor is 3.10 (`python_floor_lint.py`). Named by this file's own directory, since
# the callers run it isolated (`python3 -I`), which leaves the script's directory off the path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from wz_config import read_decl_toml  # noqa: E402

PROSE_KEYS = ("decision", "changes", "verification", "carry")
KEYS = ("impact",) + PROSE_KEYS

#: `append-round.sh`'s arguments a descriptor carries, and the key each one fills.
ROUND_ARGS = {
    "--decision-file": "decision",
    "--changes-file": "changes",
    "--verification-file": "verification",
    "--carry-file": "carry",
    "--impact": "impact",
}

#: What a `'''` string cannot hold as it is. TOML refuses the control characters but tab
#: in a literal string, and the floor reader splits its document with `str.splitlines`,
#: which also breaks a line at U+0085, U+2028 and U+2029, so prose holding any of them
#: would read back as other text.
_NOT_LITERAL = re.compile("'''|[\x00-\x08\x0b-\x1f\x7f\x85\U00002028\U00002029]")


class NotARound(Exception):
    """The descriptor cannot be filed as a round; the message says which rule."""


def read(path: Path) -> dict:
    """The descriptor as a validated mapping, or `NotARound` naming the rule broken."""
    try:
        raw = path.read_bytes()
    except OSError as err:
        raise NotARound(f"{path}: cannot be read: {err}") from err
    try:
        data = read_decl_toml(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        raise NotARound(f"{path}: not a TOML document: {err}") from err
    unknown = sorted(set(data) - set(KEYS))
    if unknown:
        raise NotARound(f"{path}: unknown key(s) {', '.join(unknown)}; a round has exactly {', '.join(KEYS)}")
    for key in KEYS:
        if key not in data:
            raise NotARound(f"{path}: key `{key}` is missing")
    impact = data["impact"]
    if not isinstance(impact, list) or not impact or not all(isinstance(i, str) and i.strip() for i in impact):
        raise NotARound(f"{path}: `impact` must be a non-empty list of section ids")
    if any("," in i for i in impact):
        raise NotARound(f"{path}: an impact id holds a comma, which --impact reads as two ids")
    for key in PROSE_KEYS:
        value = data[key]
        if not isinstance(value, str) or not value.strip():
            raise NotARound(f"{path}: `{key}` must be a non-empty string")
    return data


def emit(path: Path, outdir: Path) -> str:
    """Write the four prose files and return the impact ids as `--impact` takes them."""
    data = read(path)
    outdir.mkdir(parents=True, exist_ok=True)
    for key in PROSE_KEYS:
        text = data[key].strip("\n") + "\n"
        (outdir / f"{key}.txt").write_text(text, encoding="utf-8")
    return ",".join(i.strip() for i in data["impact"])


def parse_round_args(args: list[str]) -> dict[str, str]:
    """`append-round.sh`'s arguments as `{key: value}`: each prose key's file, and `impact`."""
    given: dict[str, str] = {}
    at = 0
    while at < len(args):
        arg = args[at]
        name, eq, value = arg.partition("=")
        if name == "--entry-id":
            raise NotARound("--entry-id is refused: a round's number is the store's on the tree it lands on")
        if name not in ROUND_ARGS:
            raise NotARound(f"`{arg}` is not an argument a round carries; it takes {', '.join(ROUND_ARGS)}")
        if not eq:
            if at + 1 >= len(args):
                raise NotARound(f"`{name}` has no value")
            at += 1
            value = args[at]
        key = ROUND_ARGS[name]
        if key in given:
            raise NotARound(f"`{name}` is given twice")
        given[key] = value
        at += 1
    missing = [name for name, key in ROUND_ARGS.items() if key not in given]
    if missing:
        raise NotARound(f"missing {', '.join(missing)}")
    return given


#: What `json.dumps` leaves bare that TOML refuses (DEL) or that the floor reader's
#: `str.splitlines` would break a line at.
_JSON_BARE = {"\x7f": "\\u007f", "\x85": "\\u0085", "\U00002028": "\\u2028", "\U00002029": "\\u2029"}


def _one_line(value: object) -> str:
    """`value` as a one-line JSON value, which is also a TOML basic string or string array."""
    text = json.dumps(value, ensure_ascii=False)
    for bare, escaped in _JSON_BARE.items():
        text = text.replace(bare, escaped)
    return text


def _toml_string(key: str, text: str) -> str:
    """`key = <text>` as one entry the floor reader and TOML both read back as `text`."""
    if text.endswith("\n") and not _NOT_LITERAL.search(text):
        return f"{key} = '''\n{text}'''\n"
    return f"{key} = {_one_line(text)}\n"


def render(fields: dict[str, object]) -> str:
    """The descriptor's text for `impact` (a list of ids) and the four prose strings."""
    lines = [f"impact = {_one_line(fields['impact'])}\n"]
    lines += [_toml_string(key, str(fields[key])) for key in PROSE_KEYS]
    return "".join(lines)


def write(path: Path, args: list[str]) -> None:
    """A new descriptor at `path` from `append-round.sh`'s arguments, read back before it stays."""
    given = parse_round_args(args)
    if path.exists():
        raise NotARound(f"{path}: exists; a descriptor is never written over")
    fields: dict[str, object] = {"impact": [i.strip() for i in given["impact"].split(",")]}
    for key in PROSE_KEYS:
        source = Path(given[key])
        try:
            text = source.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as err:
            raise NotARound(f"{source}: cannot be read: {err}") from err
        fields[key] = text.strip("\n") + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(fields), encoding="utf-8")
    try:
        back = read(path)
        if back != fields:
            raise NotARound(f"{path}: does not read back as it was written")
    except NotARound:
        path.unlink()
        raise


def selftest() -> int:
    good = (
        'impact = ["a/b", "c/d"]\n'
        "decision = '''why'''\nchanges = '''what'''\n"
        "verification = '''how'''\ncarry = '''open'''\n"
    )
    arms: list[tuple[str, str, str | None]] = [
        ("a complete round is read", good, None),
        ("a missing key is refused", good.replace("carry = '''open'''\n", ""), "`carry` is missing"),
        ("an unknown key is refused", good + "round = 4400\n", "unknown key(s) round"),
        ("an empty impact is refused", good.replace('["a/b", "c/d"]', "[]"), "non-empty list"),
        # The floor reader reads an array of strings only, so a number among the ids is refused
        # as no document before the impact rule is asked.
        ("a non-string impact id is refused", good.replace('"a/b"', "7"), "not a TOML document"),
        ("an impact that is no list is refused", good.replace('["a/b", "c/d"]', '"a/b"'), "non-empty list"),
        ("a comma in an id is refused", good.replace('"a/b"', '"a,b"'), "holds a comma"),
        ("an empty prose field is refused", good.replace("'''why'''", "'''  '''"), "`decision` must be"),
        ("a non-TOML file is refused", "this is = = not toml", "not a TOML document"),
    ]
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, text, refusal in arms:
            descriptor = root / "round.toml"
            descriptor.write_text(text, encoding="utf-8")
            try:
                impact = emit(descriptor, root / "out")
            except NotARound as err:
                ok = refusal is not None and refusal in str(err)
                detail = str(err)
            else:
                ok = refusal is None and impact == "a/b,c/d"
                detail = f"filed with impact {impact!r}"
            print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f": {detail}"))
            failed += 0 if ok else 1
        files = sorted(p.name for p in (root / "out").iterdir())
        ok = files == ["carry.txt", "changes.txt", "decision.txt", "verification.txt"]
        print(f"  {'ok  ' if ok else 'FAIL'} the four prose files are written: {files}")
        failed += 0 if ok else 1
        (root / "round.toml").write_text(good, encoding="utf-8")
        emit(root / "round.toml", root / "again")
        ok = (root / "again" / "decision.txt").read_text() == "why\n"
        print(f"  {'ok  ' if ok else 'FAIL'} the prose is written with one closing newline")
        failed += 0 if ok else 1
        write_failed, write_total = _selftest_write(root / "write")
        failed += write_failed
    total = len(arms) + 2 + write_total
    print(f"round_descriptor selftest: {total - failed}/{total} arm(s) pass")
    return 1 if failed else 0


def _selftest_write(root: Path) -> tuple[int, int]:
    """`write`'s arms in `root`: (failed, total)."""
    root.mkdir()
    prose = {
        "decision": "why\n\nit is so\n",
        "changes": "what",
        "verification": "how ''' closed",
        "carry": "open \x7f\U00002028 \U0001f600 \t tab",
    }
    for key, text in prose.items():
        (root / f"{key}.txt").write_text(text, encoding="utf-8")

    def args(**override: str) -> list[str]:
        given = {name: str(root / f"{key}.txt") for name, key in ROUND_ARGS.items() if key != "impact"}
        given["--impact"] = "a/b, c/d"
        given.update({"--" + k.replace("_", "-"): v for k, v in override.items()})
        return [part for name, value in given.items() for part in (name, value)]

    failed = 0
    total = 0

    def arm(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failed, total
        total += 1
        failed += 0 if ok else 1
        print(f"  {'ok  ' if ok else 'FAIL'} write: {name}" + ("" if ok else f": {detail}"))

    target = root / "pending" / "one.toml"
    write(target, args())
    text = target.read_text(encoding="utf-8")
    back = read(target)
    arm(
        "plain prose is a ''' string and reads back with one closing newline",
        "decision = '''\n" in text and back["decision"] == "why\n\nit is so\n" and back["changes"] == "what\n",
        text,
    )
    arm(
        "prose holding ''' is a one-line string and reads back as written",
        'verification = "' in text and back["verification"] == "how ''' closed\n",
        text,
    )
    arm(
        "DEL and U+2028 are escaped, a character beyond the BMP stays as it is",
        "\x7f" not in text
        and "\U00002028" not in text
        and "\U0001f600" in text
        and back["carry"] == "open \x7f\U00002028 \U0001f600 \t tab\n",
        text,
    )
    arm("the impact ids are split at commas and trimmed", back["impact"] == ["a/b", "c/d"], repr(back["impact"]))
    out = root / "emitted"
    arm("emit gives the ids as --impact takes them", emit(target, out) == "a/b,c/d")

    eq_form = [f"{name}={value}" for name, value in zip(args()[::2], args()[1::2])]
    write(root / "eq.toml", eq_form)
    arm("the `--x=v` form is read as `--x v`", read(root / "eq.toml") == back)

    refusals: list[tuple[str, list[str], str]] = [
        ("--entry-id is refused", args() + ["--entry-id", "Round 9"], "--entry-id is refused"),
        ("an argument append-round takes but a round does not", args() + ["--check-only"], "not an argument"),
        ("a missing prose file argument", args()[:4] + args()[6:], "missing --verification-file"),
        ("an argument given twice", args() + ["--impact", "e/f"], "given twice"),
        ("an argument with no value", args() + ["--carry-file"], "has no value"),
        ("a prose file that cannot be read", args(carry_file=str(root / "absent.txt")), "cannot be read"),
        ("an empty impact id", args(impact="a/b,,c/d"), "non-empty list"),
    ]
    for name, given, refusal in refusals:
        path = root / "refused.toml"
        try:
            write(path, given)
        except NotARound as err:
            arm(f"{name} (nothing is left behind)", refusal in str(err) and not path.exists(), str(err))
        else:
            arm(name, False, "written")
            path.unlink()
    try:
        write(target, args())
    except NotARound as err:
        arm("an existing descriptor is never written over", "never written over" in str(err), str(err))
    else:
        arm("an existing descriptor is never written over", False, "written")
    (root / "blank.txt").write_text("\n\n", encoding="utf-8")
    try:
        write(root / "blank.toml", args(decision_file=str(root / "blank.txt")))
    except NotARound as err:
        arm(
            "empty prose is refused and its file removed",
            "`decision` must be" in str(err) and not (root / "blank.toml").exists(),
            str(err),
        )
    else:
        arm("empty prose is refused and its file removed", False, "written")
    return failed, total


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if len(argv) == 3 and argv[0] == "emit":
        try:
            print(emit(Path(argv[1]), Path(argv[2])))
        except NotARound as err:
            print(f"round_descriptor: REFUSED {err}", file=sys.stderr)
            return 1
        return 0
    if len(argv) >= 2 and argv[0] == "write":
        try:
            write(Path(argv[1]), argv[2:])
        except NotARound as err:
            print(f"round_descriptor: REFUSED {err}", file=sys.stderr)
            return 1
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
