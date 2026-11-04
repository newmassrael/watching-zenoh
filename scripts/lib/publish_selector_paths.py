#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4234 (no register item) -- the registry of every fact the dissection's
declared shape has published to a selector (`crates/wz-session-core/src/published_selector_paths.txt`), kept as
the append-only ledger it is.

    publish_selector_paths.py --append <log>    append the facts a test log names
    publish_selector_paths.py --check <ref>     refuse a line <ref> published and
                                                this tree lost or changed
    publish_selector_paths.py --selftest        check both against fixtures

## Why a ledger, and why this script

A path a selector names is a name a consumer keeps: in a saved selector, in the
`selector_path` of a document it stored. A fact once published (a path, the kind
it is read at, a word of a closed label) is therefore never taken back; a field
that moves is renamed (`dissect_schema::RENAMED`) and its former name still
resolves. The Rust test `dissect_schema::tests::every_published_fact_still_holds`
holds the shape to every line, and prints each fact the shape declares that is
not published yet as `PUBLISH\\t<fact>`.

Two things the test cannot do are done here. It cannot WRITE the ledger (a test
does not edit the tree it tests), so `--append` reads those lines out of the
test's output and appends them, refusing anything that is not a fact line. And
it cannot see HISTORY: a commit that removes a line and the path together leaves
a ledger the test agrees with. `--check <ref>` compares the ledger with the one
`<ref>` holds and refuses every line that ref published and this tree does not
hold verbatim.

Exit codes: 0 pass; 1 the ledger lost a line, or a log line is not a fact; 2
usage.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
LEDGER_REL = "crates/wz-session-core/src/published_selector_paths.txt"
LEDGER = ROOT / LEDGER_REL
MARK = "PUBLISH\t"
KINDS = {"bits", "bytes", "flag", "label", "nested", "opaque", "text", "uint", "zid"}


def facts(text: str) -> list[str]:
    """The fact lines of a ledger: every line that is neither blank nor a
    comment."""
    return [line for line in text.splitlines() if line and not line.startswith("#")]


def is_fact(line: str) -> bool:
    """`<path>\\t<kind>`, or `<path>\\t<label>\\t<word>`."""
    parts = line.split("\t")
    if len(parts) not in (2, 3) or not all(parts):
        return False
    path, kind = parts[0], parts[1]
    if kind not in KINDS or any(not seg for seg in path.split(".")):
        return False
    return len(parts) == 2 or kind == "label"


def published_in(log: str) -> list[str]:
    """The facts a test log names after `PUBLISH\\t`, in order, each once."""
    out: list[str] = []
    for line in log.splitlines():
        if line.startswith(MARK):
            fact = line[len(MARK):]
            if fact not in out:
                out.append(fact)
    return out


def append(ledger_text: str, log: str) -> tuple[str, list[str], list[str]]:
    """The ledger with the log's new facts appended; the facts appended; the
    log lines refused."""
    have = set(facts(ledger_text))
    new, refused = [], []
    for fact in published_in(log):
        if not is_fact(fact):
            refused.append(fact)
        elif fact not in have:
            new.append(fact)
            have.add(fact)
    text = ledger_text if ledger_text.endswith("\n") or not ledger_text else ledger_text + "\n"
    return text + "".join(f"{fact}\n" for fact in new), new, refused


def lost(before: str, after: str) -> list[str]:
    """The fact lines `before` holds that `after` does not hold verbatim."""
    kept = set(facts(after))
    return [fact for fact in facts(before) if fact not in kept]


def ledger_at(ref: str) -> str | None:
    """The ledger as `ref` holds it, or None where that ref has none yet."""
    result = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{ref}:{LEDGER_REL}"],
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def selftest() -> int:
    ledger = "# head\nPush\tnested\nPush.qos.priority\tlabel\tData\n"
    log = (
        "noise\nPUBLISH\tPush.put\tnested\nPUBLISH\tPush\tnested\n"
        "PUBLISH\tPush.put\tnested\nPUBLISH\tPush.x\tlabel\nPUBLISH\tPush.y\tuint\tw\n"
    )
    text, new, refused = append(ledger, log)
    checks = [
        (new == ["Push.put\tnested", "Push.x\tlabel"], f"appended {new}"),
        (refused == ["Push.y\tuint\tw"], f"refused {refused}: a word is a label's alone"),
        (text.startswith(ledger), "the ledger's lines stay where they were"),
        (lost(ledger, text) == [], "an append loses nothing"),
        (lost(ledger, "# head\nPush\tnested\n") == ["Push.qos.priority\tlabel\tData"], "a removal is seen"),
        (lost(ledger, ledger.replace("Data", "DataHigh")) == ["Push.qos.priority\tlabel\tData"], "an edit is seen"),
        (is_fact("Push.x\tlabel"), "a label path alone is a fact"),
        (not is_fact("Push..x\tuint"), "an empty segment is not"),
        (not is_fact("Push.x\tnumber"), "an unknown kind is not"),
    ]
    failed = [why for ok, why in checks if not ok]
    for why in failed:
        print(f"publish_selector_paths: selftest FAIL -- {why}", file=sys.stderr)
    if failed:
        return 1
    print("publish_selector_paths: selftest OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if len(argv) == 2 and argv[0] == "--append":
        log = pathlib.Path(argv[1]).read_text(errors="replace")
        text, new, refused = append(LEDGER.read_text(), log)
        for fact in refused:
            print(f"publish_selector_paths: REFUSED -- not a fact line: {fact!r}", file=sys.stderr)
        if refused:
            return 1
        LEDGER.write_text(text)
        print(f"publish_selector_paths: {len(new)} fact(s) appended; {len(facts(text))} published")
        return 0
    if len(argv) == 2 and argv[0] == "--check":
        before = ledger_at(argv[1])
        if before is None:
            print(f"publish_selector_paths: {argv[1]} holds no ledger yet; nothing to keep")
            return 0
        gone = lost(before, LEDGER.read_text())
        for fact in gone:
            print(f"publish_selector_paths: FAIL -- {argv[1]} published {fact!r} and the "
                  "ledger no longer holds it. A published fact is never taken back: "
                  "rename the field (dissect_schema::RENAMED) instead.", file=sys.stderr)
        if gone:
            return 1
        print(f"publish_selector_paths: every fact {argv[1]} published is still published "
              f"({len(facts(before))} then, {len(facts(LEDGER.read_text()))} now)")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
