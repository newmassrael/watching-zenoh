#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The limits an image can state for itself, declared once and offered to Kconfig.

## What this is

`crates/wz-session-core/src/caps.rs` holds the capacity constants every bounded table of a session is
sized by. Each one is `limit(option_env!("WZ_LIMIT_<NAME>"), <default>)`: the default when the build
says nothing, the number its environment states when it does. That row is the declaration. This tool
is what derives from it:

    --emit-kconfig    print deploy/Kconfig.limits (one `int` symbol per limit, `CONFIG_WZ_LIMIT_<NAME>`)
    --check           hold the committed Kconfig and the rows of caps.rs to the rules below
    --selftest        drive the reader on a sample and on each way a row can be wrong

The Zephyr build turns every `CONFIG_WZ_LIMIT_<NAME>` into the environment variable of the same name
without `CONFIG_` for the cargo build (deploy/zephyr-common/wz_zephyr_board.cmake), so an overlay that
sets `CONFIG_WZ_LIMIT_MAX_QUERYABLES=2` sizes the queryable table of that image and no other.

## Why the declaration is the Rust row and not a table beside it

A second file that listed the names and defaults would be a second place for them to differ. The row
in caps.rs is the place the default is READ from, so deriving the Kconfig from it leaves nothing to
keep in step but the one generated file, which `--check` holds.

## The rules `--check` holds

  1. deploy/Kconfig.limits equals what `--emit-kconfig` prints now.
  2. In every row the name in `WZ_LIMIT_<NAME>` is the name of the constant: a row that stated another
     name would be read by nobody.
  3. No `pub const <NAME>: usize = <number>;` in caps.rs is a bare literal: a limit that bypasses
     `limit(...)` could not be stated by an image, and would not be in the Kconfig.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CAPS = ROOT / "crates" / "wz-session-core" / "src" / "caps.rs"
KCONFIG = ROOT / "deploy" / "Kconfig.limits"

ROW = re.compile(
    r'pub const (?P<name>[A-Z0-9_]+): usize =\s*limit\(option_env!\("WZ_LIMIT_(?P<env>[A-Z0-9_]+)"\), (?P<default>\d+)\);'
)
BARE = re.compile(r"^pub const (?P<name>[A-Z0-9_]+): usize = \d+;", re.MULTILINE)


class Limit:
    def __init__(self, name: str, env: str, default: int, doc: list[str]):
        self.name, self.env, self.default, self.doc = name, env, default, doc


def read(text: str) -> list[Limit]:
    """The limits of a caps.rs text, in file order, each with the first paragraph of its docs."""
    lines = text.splitlines()
    found: list[Limit] = []
    for m in ROW.finditer(text):
        line_no = text.count("\n", 0, m.start())
        doc: list[str] = []
        i = line_no - 1
        while i >= 0 and lines[i].startswith("///"):
            doc.append(lines[i][3:].strip())
            i -= 1
        doc.reverse()
        paragraph: list[str] = []
        for line in doc:
            if not line:
                break
            paragraph.append(line)
        found.append(Limit(m.group("name"), m.group("env"), int(m.group("default")), paragraph))
    return found


def emit(limits: list[Limit]) -> str:
    out = [
        "# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial",
        "# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael",
        "#",
        "# GENERATED from crates/wz-session-core/src/caps.rs by scripts/lib/limit_config.py --emit-kconfig.",
        "# Do not edit: `limit_config.py --check` fails when this file is stale.",
        "",
        'menu "wz limits"',
        "",
        "comment \"Each limit sizes a table of every session of the image; a build states its own.\"",
        "",
    ]
    for lim in limits:
        out.append(f"config WZ_LIMIT_{lim.env}")
        out.append(f'\tint "{lim.name}"')
        out.append(f"\tdefault {lim.default}")
        out.append("\thelp")
        for line in lim.doc:
            out.append(f"\t  {line}" if line else "\t")
        out.append("")
    out.append("endmenu")
    return "\n".join(out) + "\n"


def problems(text: str, committed: str | None) -> list[str]:
    bad: list[str] = []
    limits = read(text)
    if not limits:
        bad.append("caps.rs holds no limit row: the reader found nothing to derive from")
    for lim in limits:
        if lim.env != lim.name:
            bad.append(f"{lim.name}: its row states WZ_LIMIT_{lim.env}, which nothing reads")
    for m in BARE.finditer(text):
        bad.append(f"{m.group('name')}: a bare literal; it cannot be stated by an image")
    if committed is not None and committed != emit(limits):
        bad.append("deploy/Kconfig.limits is stale: run limit_config.py --emit-kconfig")
    return bad


SAMPLE = """\
/// A table.
///
/// More.
pub const MAX_A: usize = limit(option_env!("WZ_LIMIT_MAX_A"), 4);
pub const MAX_B: usize =
    limit(option_env!("WZ_LIMIT_MAX_B"), 8);
"""


def selftest() -> int:
    limits = read(SAMPLE)
    assert [(l.name, l.default) for l in limits] == [("MAX_A", 4), ("MAX_B", 8)], limits
    assert limits[0].doc == ["A table."], limits[0].doc
    assert problems(SAMPLE, emit(read(SAMPLE))) == [], "a clean sample must pass"
    assert problems(SAMPLE, "stale\n"), "a stale Kconfig must fail"
    wrong = SAMPLE.replace('"WZ_LIMIT_MAX_B"', '"WZ_LIMIT_MAX_C"')
    assert any("nothing reads" in p for p in problems(wrong, None)), "a mismatched name must fail"
    bare = SAMPLE + "pub const MAX_D: usize = 3;\n"
    assert any("bare literal" in p for p in problems(bare, None)), "a bare literal must fail"
    assert problems("", None), "an empty file must fail"
    print("limit-config: selftest OK")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("--check", "--emit-kconfig", "--selftest"):
        print(__doc__)
        return 2
    if argv[1] == "--selftest":
        return selftest()
    text = CAPS.read_text()
    if argv[1] == "--emit-kconfig":
        sys.stdout.write(emit(read(text)))
        return 0
    committed = KCONFIG.read_text() if KCONFIG.exists() else None
    bad = problems(text, committed if committed is not None else "")
    if bad:
        for line in bad:
            print(f"limit-config: FAIL {line}")
        return 1
    print(f"limit-config: OK -- {len(read(text))} limit(s), Kconfig current")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
