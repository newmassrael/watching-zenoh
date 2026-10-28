#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""The text of a final MCU image, told by who owns it, held against committed rows.

## What was missing

The resource budget holds the stack of an image to a committed figure and says why it moved. The
text of the same image was held to nothing but the parity matrix's total: 176 KB against 145 KB,
a gap of 31 KB, with no row that said which part of it was whose. A lever on size (a build flag,
a feature, a shared copy of a generic function) was then chosen by a guess about where the bytes
were, and its worth could be read only as a change of the total.

## What is held

For each image of `deploy/text_budget.json` this reads the symbol table of the linked ELF
(`nm -S -C`), gives every symbol of code or read-only data to an owner, and holds three things:

- the image's text (`size`'s first column) to the committed figure, within `text_tolerance_bytes`;
- every committed owner to its figure, within `owner_tolerance_bytes`;
- no owner above `MIN_OWNER_BYTES` that the row does not name, and the owners below it summed
  into one row (`(smaller owners)`), so that a new crate or a new C library is a finding.

A change that moves the text by more than a tolerance is a recorded change: the row moves in the
same commit, with the reason in its `measured` text.

## Who owns a symbol

A Rust symbol belongs to the first crate its demangled path names (`<wz_codecs::x::Y as T>::f`
belongs to `wz_codecs`). A C symbol belongs to its prefix, named as the prefix (`c:_z_`), because
a prefix is a fact about the name and not a claim about the library: `z_` is both Zephyr's
internals and zenoh-pico's API.

This is the owner of the SYMBOL. With link-time inlining the symbol that carries a function's code
is the caller's, so a callee inlined into `wz_app_main` is counted under `c:wz_`. The rows are a
fence around a total and a way to find where a change landed; they do not say whose source a byte
came from. Provenance needs a build without LTO, which has other sizes.

## Modes

`--check KEY --elf ELF` judges one built image; `--emit KEY --elf ELF` prints the row for the
image as built (to be committed by hand with the reason); `--selftest` drives the reader and the
rule; `--list` prints the keys.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUDGET = ROOT / "deploy" / "text_budget.json"

#: An owner below this is summed into the one `SMALL` row.
MIN_OWNER_BYTES = 512
SMALL = "(smaller owners)"
NO_SYMBOL = "(no symbol)"

CODE_KINDS = frozenset("TtWw")
READ_ONLY_KINDS = frozenset("RrVv")

_RUST_OWNER = re.compile(r"^<?(?:&(?:mut )?)?([a-z_][a-z0-9_]*)::")

#: C prefixes, longest first so that `_z_` is not read as `_`.
_C_PREFIXES = ("_z_", "zsock", "zvfs", "zp_", "z_", "sys_", "net_", "k_", "wz_", "__")


def owner_of(name: str) -> str:
    """The owner of one demangled symbol name."""
    found = _RUST_OWNER.match(name)
    if found:
        return found.group(1)
    if "::" in name:
        return "rust:other"
    for prefix in _C_PREFIXES:
        if name.startswith(prefix):
            return f"c:{prefix}"
    return "c:" + (name.split("_", 1)[0] if "_" in name else "other")


def owners(nm_output: str) -> dict[str, int]:
    """Bytes of code and read-only data by owner, from `nm -S -C` output."""
    total: dict[str, int] = {}
    for line in nm_output.splitlines():
        parts = line.rstrip("\n").split(" ", 3)
        if len(parts) < 4:
            continue
        try:
            size = int(parts[1], 16)
        except ValueError:
            continue
        kind, name = parts[2], parts[3]
        if kind not in CODE_KINDS and kind not in READ_ONLY_KINDS:
            continue
        key = owner_of(name)
        total[key] = total.get(key, 0) + size
    return total


def fold(owned: dict[str, int], image_text: int) -> dict[str, int]:
    """The rows of an image: the owners over the floor, the rest summed, and what has no symbol."""
    rows = {k: v for k, v in owned.items() if v >= MIN_OWNER_BYTES}
    small = sum(v for v in owned.values() if v < MIN_OWNER_BYTES)
    if small:
        rows[SMALL] = small
    unnamed = image_text - sum(owned.values())
    if unnamed > 0:
        rows[NO_SYMBOL] = unnamed
    return dict(sorted(rows.items(), key=lambda kv: (-kv[1], kv[0])))


def judge(row: dict, image_text: int, folded: dict[str, int]) -> list[str]:
    """The findings of one image against its committed row (empty when it holds)."""
    findings: list[str] = []
    text_tolerance = int(row["text_tolerance_bytes"])
    owner_tolerance = int(row["owner_tolerance_bytes"])
    committed_text = int(row["text_bytes"])
    if abs(image_text - committed_text) > text_tolerance:
        findings.append(
            f"the text is {image_text} bytes, the committed figure is {committed_text} "
            f"(tolerance {text_tolerance}); commit the new figure with its reason"
        )
    committed = row["owners"]
    for name, figure in committed.items():
        now = folded.get(name, 0)
        if abs(now - int(figure)) > owner_tolerance:
            findings.append(
                f"owner {name}: {now} bytes, the committed figure is {figure} "
                f"(tolerance {owner_tolerance})"
            )
    for name, now in folded.items():
        if name not in committed:
            findings.append(f"owner {name}: {now} bytes and no committed row")
    return findings


def tool(names: tuple[str, ...]) -> str:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    raise SystemExit(f"text-owner: none of {', '.join(names)} is on PATH")


def read_elf(elf: str, nm_arg: str | None, size_arg: str | None) -> tuple[int, dict[str, int]]:
    """The image's text and its owners, from a linked ELF."""
    nm = nm_arg or tool(("arm-none-eabi-nm", "llvm-nm", "nm"))
    size = size_arg or tool(("arm-none-eabi-size", "llvm-size", "size"))
    listing = subprocess.run(
        [nm, "-S", "-C", elf], check=True, capture_output=True, text=True
    ).stdout
    berkeley = subprocess.run([size, elf], check=True, capture_output=True, text=True).stdout
    lines = berkeley.strip().splitlines()
    image_text = int(lines[1].split()[0])
    return image_text, owners(listing)


def load() -> dict:
    return json.loads(BUDGET.read_text(encoding="utf-8"))


def check(key: str, elf: str, nm_arg: str | None, size_arg: str | None) -> int:
    images = load()["images"]
    if key not in images:
        print(f"text-owner: FAIL {key}: no row in {BUDGET.relative_to(ROOT)}; run --emit and commit it")
        return 1
    image_text, owned = read_elf(elf, nm_arg, size_arg)
    folded = fold(owned, image_text)
    findings = judge(images[key], image_text, folded)
    if findings:
        for finding in findings:
            print(f"text-owner: FAIL {key}: {finding}")
        return 1
    print(
        f"text-owner: OK {key}: text {image_text} bytes against the committed "
        f"{images[key]['text_bytes']}, {len(folded)} owners within {images[key]['owner_tolerance_bytes']}"
    )
    return 0


def emit(key: str, elf: str, nm_arg: str | None, size_arg: str | None) -> int:
    image_text, owned = read_elf(elf, nm_arg, size_arg)
    folded = fold(owned, image_text)
    row = {
        "text_bytes": image_text,
        "text_tolerance_bytes": 1024,
        "owner_tolerance_bytes": 1024,
        "owners": folded,
    }
    print(json.dumps({key: row}, indent=2))
    return 0


def selftest() -> int:
    failures: list[str] = []

    def expect(what: str, got, want) -> None:
        if got != want:
            failures.append(f"{what}: got {got!r}, wanted {want!r}")

    expect("a crate path", owner_of("wz_session_core::query::dispatch"), "wz_session_core")
    expect("a trait impl", owner_of("<wz_codecs::response::Response as core::fmt::Debug>::fmt"), "wz_codecs")
    expect("a reference", owner_of("<&mut sce_rust_runtime::Sink as T>::f"), "sce_rust_runtime")
    expect("a pico prefix", owner_of("_z_session_open"), "c:_z_")
    expect("an ambiguous prefix", owner_of("z_impl_k_sleep"), "c:z_")
    expect("an unprefixed C name", owner_of("memcpy"), "c:other")
    expect("an underscored C name", owner_of("ethernet_init"), "c:ethernet")

    listing = "\n".join(
        [
            "00000000 00000400 T wz_session_core::a",
            "00000400 00000400 t wz_session_core::b",
            "00000800 00000100 R wz_codecs::TABLE",
            "00000900 00000100 t wz_codecs::c",
            "00000a00 00000200 B wz_session_core::STATE",
            "00000c00 00000010 T _z_tiny",
        ]
    )
    got = owners(listing)
    expect("owners sum code and read-only data", got.get("wz_session_core"), 0x800)
    expect("a bss symbol is not text", "STATE" in got, False)
    expect("owners below the floor", got.get("c:_z_"), 0x10)
    folded = fold(got, 0x800 + 0x200 + 0x10 + 0x40)
    expect("a small owner is summed", folded.get(SMALL), 0x10)
    expect("what has no symbol", folded.get(NO_SYMBOL), 0x40)

    row = {
        "text_bytes": 3000,
        "text_tolerance_bytes": 100,
        "owner_tolerance_bytes": 100,
        "owners": {"wz_session_core": 2048, "wz_codecs": 512, SMALL: 16, NO_SYMBOL: 64},
    }
    expect("a row that holds", judge(row, 3050, folded), [])
    expect("a text that moved", len(judge(row, 3200, folded)), 1)
    moved = dict(folded)
    moved["wz_session_core"] = 4096
    expect("an owner that moved", len(judge(row, 3050, moved)), 1)
    moved = dict(folded)
    moved["keccak"] = 2164
    expect("an owner with no row", len(judge(row, 3050, moved)), 1)

    if failures:
        for failure in failures:
            print(f"text-owner: selftest FAIL -- {failure}")
        return 1
    print(
        "text-owner: selftest OK -- reads crate paths, trait impls and C prefixes, sums code and "
        "read-only data and not bss, folds the small owners, and judges a moved text, a moved "
        "owner and an owner with no row"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", metavar="KEY", help="judge one built image")
    mode.add_argument("--emit", metavar="KEY", help="print the row of one built image")
    mode.add_argument("--selftest", action="store_true", help="drive the reader and the rule")
    mode.add_argument("--list", action="store_true", help="print the image keys")
    parser.add_argument("--elf", help="the built ELF")
    parser.add_argument("--nm", help="the nm of the toolchain that linked the ELF")
    parser.add_argument("--size", help="the size of the toolchain that linked the ELF")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.list:
        print("\n".join(load()["images"]))
        return 0
    if not args.elf:
        parser.error("--check and --emit need --elf")
    if args.emit:
        return emit(args.emit, args.elf, args.nm, args.size)
    return check(args.check, args.elf, args.nm, args.size)


if __name__ == "__main__":
    sys.exit(main())
