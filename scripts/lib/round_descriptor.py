#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""A ledger round written down as DATA, so it can travel in a commit.

`scripts/land.sh` takes the round's prose from four files outside the repository and
the round's number from the store inside its lock. A commit cannot carry either, so a
queue integrator, which cherry-picks a commit onto the remote tip and files nothing,
has nowhere to read a round from. A descriptor is the same round as one tracked file:
the prose, the impact ids and no number. The number is the one fact the commit cannot
know, because it is the store's last round plus one at the moment the commit lands, so
it is not in the descriptor and `scripts/file-round.sh` computes it on the candidate.

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
    round_descriptor.py --selftest                   every refusal and the happy path

Exit 0 ok; 1 the descriptor is not a round; 2 usage.
"""

from __future__ import annotations

import sys
import tempfile
import tomllib
from pathlib import Path

PROSE_KEYS = ("decision", "changes", "verification", "carry")
KEYS = ("impact",) + PROSE_KEYS


class NotARound(Exception):
    """The descriptor cannot be filed as a round; the message says which rule."""


def read(path: Path) -> dict:
    """The descriptor as a validated mapping, or `NotARound` naming the rule broken."""
    try:
        raw = path.read_bytes()
    except OSError as err:
        raise NotARound(f"{path}: cannot be read: {err}") from err
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as err:
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
        ("a non-string impact id is refused", good.replace('"a/b"', "7"), "non-empty list"),
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
    total = len(arms) + 2
    print(f"round_descriptor selftest: {total - failed}/{total} arm(s) pass")
    return 1 if failed else 0


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
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
