#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2463 (no register item) — HOLD THE C CONSUMER'S DOCUMENT-REVISION LITERALS
TO `doc_revision::DOCUMENT_HISTORY`, locally and in one second.

The citation is `no register item` on `capi_replay_vocabulary.py`'s precedent
and for its reason: the item this gate answers for -- unregistered open-debt
item 695, the hosted reds nobody attributes -- lives in a register OUTSIDE this
repository, so `debt_plane_census.py` cannot resolve a number here. The item is
named in full so a reader grepping for it lands on this file.

## The class this gate is for, and why a comment was not enough

`crates/wz-capi-dissect/tests/c_abi_consumer.c` asserts that each document
OPENS with its own name and revision, and it builds the expected prefix from a
LITERAL it carries. The number therefore lives in two crates: the SSOT is
`wz-capture`'s `DOCUMENT_HISTORY`, and the copy is a C file compiled only by
Layer C1bo. So the crate that MOVES the revision is not the crate that fails,
which is exactly the shape `config_key_fixture_gate.py` was written for one
door over -- and `cargo test -p wz-capture` cannot see it by construction.

MEASURED, not argued. The C file's own comment already records this happening:
"BOTH OF THOSE LEFT THIS LITERAL AT 5, so this row was red BEHIND the census
row above -- a second stale pin the loop could not report, because it stops at
the first." That was R2447 and R2453. It then happened twice more, in the two
rounds immediately before this one: R2457 moved `census` 10 -> 11 (item 702)
and R2458 moved `fields` 8 -> 9 (item 703), and neither moved the literal. Four
leaks of one class is this workspace's own threshold for building an instrument
instead of writing another comment.

## Why it checks ALL rows rather than the first

The C loop is fail-fast: `CHECK` aborts, so Layer C1bo reports exactly one
stale pin however many there are, and repairing the row that fired MOVES the
failure rather than reducing it. That is the whole reason the second leak above
went unseen behind the first. This gate reports every mismatch in one run.

## The anti-vacuity arm, which is the half a gate like this usually lacks

A parser that silently matches nothing reports green, and a green that means
"there was nothing to check" is indistinguishable from a green that means "it
agrees". So an empty population on EITHER side is a FAIL, and the counts are
PRINTED -- a reader can tell a pass from a lane that measured nothing without
taking this file's word for it.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SSOT = ROOT / "crates/wz-capture/src/doc_revision.rs"
CONSUMER = ROOT / "crates/wz-capi-dissect/tests/c_abi_consumer.c"


def newest_revisions() -> dict[str, int]:
    """`document name -> the newest revision DOCUMENT_HISTORY declares for it`.

    Scoped to the `DOCUMENT_HISTORY` array rather than swept over the file: the
    word `revision:` also appears in the per-family `Shape` rows, and a sweep
    would let one of those set the ceiling for a document it says nothing
    about.
    """
    src = SSOT.read_text(encoding="utf-8")
    names = dict(
        re.findall(r"^pub const ([A-Z_]+): &str = \"([a-z_]+)\";", src, re.M)
    )
    start = src.find("pub const DOCUMENT_HISTORY: &[DocumentShape] = &[")
    if start < 0:
        fail("DOCUMENT_HISTORY was not found; a pin read from nothing is not a pin.")
    end = src.find("\n];", start)
    if end < 0:
        fail("DOCUMENT_HISTORY has no end; refusing to guess where it stops.")
    block = src[start:end]

    newest: dict[str, int] = {}
    document = None
    for line in block.splitlines():
        got = re.match(r"\s+document: ([A-Z_]+),\s*$", line)
        if got:
            document = got.group(1)
            continue
        got = re.match(r"\s+revision: (\d+),\s*$", line)
        if got and document is not None:
            name = names.get(document)
            if name is None:
                fail(f"`{document}` is used in DOCUMENT_HISTORY but names no string.")
            newest[name] = max(newest.get(name, 0), int(got.group(1)))
            document = None
    return newest


def consumer_pins() -> dict[str, int]:
    """`document name -> the revision the C consumer is written against`."""
    src = CONSUMER.read_text(encoding="utf-8")
    names = dict(
        (int(i), n)
        for i, n in re.findall(
            r"revisioned\[(\d+)\]\.name\s*=\s*\"([a-z_]+)\";", src
        )
    )
    revs = dict(
        (int(i), int(r))
        for i, r in re.findall(r"revisioned\[(\d+)\]\.revision\s*=\s*(\d+);", src)
    )
    out: dict[str, int] = {}
    for index, name in sorted(names.items()):
        if index not in revs:
            fail(f"`revisioned[{index}]` ({name}) names no revision.")
        out[name] = revs[index]
    return out


def _shown(path: pathlib.Path) -> str:
    """The path as a reader should see it: repo-relative where it is in the
    repo, and whole where it is not.

    `relative_to` RAISES rather than answering for a path outside the root, and
    the selftest's temporary fixtures are exactly that -- so the message this
    gate prints on a real failure would have been reached, in the selftest, by
    a traceback instead. Found by the selftest on its first run, which is what
    it is for.
    """
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def fail(why: str) -> None:
    print(f"doc-revision-consumer-pin: FAIL -- {why}", file=sys.stderr)
    raise SystemExit(1)


def selftest() -> int:
    """Drive every arm, because a gate is where its author is most lenient.

    Each case is a VALUE damage over a fixture that otherwise passes, which is
    the same rule the repairs this gate guards are held to: a probe that fails
    to parse would prove nothing about the predicate.
    """
    import tempfile

    ssot = (
        'pub const CENSUS: &str = "census";\n'
        'pub const FIELDS: &str = "fields";\n'
        "pub const DOCUMENT_HISTORY: &[DocumentShape] = &[\n"
        "    DocumentShape {\n        document: CENSUS,\n        revision: 1,\n    },\n"
        "    DocumentShape {\n        document: CENSUS,\n        revision: 3,\n    },\n"
        "    DocumentShape {\n        document: FIELDS,\n        revision: 2,\n    },\n"
        "];\n"
        # AFTER the array, and it must not raise the ceiling: the per-family
        # `Shape` rows carry the same word, and a sweep over the file rather
        # than over the array would let one of them speak for a document.
        "const F: Shape = Shape {\n        document: CENSUS,\n        revision: 99,\n    };\n"
    )
    consumer_ok = (
        '    revisioned[0].name = "census";\n    revisioned[0].revision = 3;\n'
        '    revisioned[1].name = "fields";\n    revisioned[1].revision = 2;\n'
    )
    cases: list[tuple[str, str, str, int]] = [
        ("the clean fixture agrees", ssot, consumer_ok, 0),
        (
            "a stale consumer pin is refused",
            ssot,
            consumer_ok.replace("revisioned[0].revision = 3", "revisioned[0].revision = 2"),
            1,
        ),
        (
            "EVERY stale pin is reported, not only the first",
            ssot,
            consumer_ok.replace("= 3", "= 1").replace("[1].revision = 2", "[1].revision = 1"),
            1,
        ),
        ("an empty consumer is refused, not passed", ssot, "", 1),
        ("an empty history is refused, not passed", "pub const X: &str = \"x\";\n", consumer_ok, 1),
        (
            "a document the history does not declare is refused",
            ssot,
            consumer_ok + '    revisioned[2].name = "ghost";\n    revisioned[2].revision = 1;\n',
            1,
        ),
    ]
    global SSOT, CONSUMER
    real = (SSOT, CONSUMER)
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, ssot_src, consumer_src, want in cases:
            SSOT = pathlib.Path(tmp) / "doc_revision.rs"
            CONSUMER = pathlib.Path(tmp) / "c_abi_consumer.c"
            SSOT.write_text(ssot_src, encoding="utf-8")
            CONSUMER.write_text(consumer_src, encoding="utf-8")
            try:
                got = main()
            except SystemExit as stop:
                got = int(stop.code or 0)
            if got != want:
                print(
                    f"doc-revision-consumer-pin: SELFTEST FAIL -- {name}: "
                    f"wanted rc={want}, got rc={got}",
                    file=sys.stderr,
                )
                failed = 1
    SSOT, CONSUMER = real
    if failed:
        return 1
    print(
        f"doc-revision-consumer-pin: selftest ok -- {len(cases)} case(s): a clean "
        f"pair, a stale pin, TWO stale pins reported together, an empty consumer, "
        f"an empty history, and a document the SSOT does not declare"
    )
    return 0


def main() -> int:
    newest = newest_revisions()
    pinned = consumer_pins()
    # The anti-vacuity arm. Either side empty means the parser stopped
    # matching, and a check with no population must not report agreement.
    if not newest:
        fail("DOCUMENT_HISTORY yielded NO document; the parser matched nothing.")
    if not pinned:
        fail("the C consumer yielded NO pinned revision; the parser matched nothing.")

    stale = []
    for name, want in sorted(pinned.items()):
        if name not in newest:
            fail(f"the C consumer pins `{name}`, which DOCUMENT_HISTORY does not declare.")
        if newest[name] != want:
            stale.append((name, want, newest[name]))

    if stale:
        for name, want, have in stale:
            print(
                f"doc-revision-consumer-pin: FAIL -- `{name}` is pinned at revision "
                f"{want} in {_shown(CONSUMER)}, but DOCUMENT_HISTORY emits "
                f"{have}. The document that moved is in another crate, so no "
                f"`cargo test -p wz-capture` can fail on this.",
                file=sys.stderr,
            )
        print(
            f"doc-revision-consumer-pin: {len(stale)} stale pin(s) of "
            f"{len(pinned)} read. Layer C1bo reports only the FIRST, so fix "
            f"every line above in one edit.",
            file=sys.stderr,
        )
        return 1

    print(
        f"doc-revision-consumer-pin: {len(pinned)} consumer pin(s) agree with "
        f"DOCUMENT_HISTORY's {len(newest)} document(s)"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--selftest"):
        # A mode is named or it is the default; an unknown argument is refused
        # by name rather than falling through to a run, which is the shape
        # `relicense_spdx.py` was repaired for.
        print(
            f"doc-revision-consumer-pin: FAIL -- unknown argument(s) "
            f"{sys.argv[1:]}; the only option is `--selftest`.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    raise SystemExit(selftest() if len(sys.argv) == 2 else main())
