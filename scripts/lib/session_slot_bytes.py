#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3312 (no register item) -- the size of ONE typed session slot, measured and held.

## What was missing

The session-slot table is `SLOT_COUNT` slots of at most `SLOT_SIZE` bytes, and the
images assert at compile time that one typed slot fits the ceiling. What the
deploy file's editor could not show was HOW MUCH of the ceiling a slot takes:
`size_of` of the slot is a number only the compiler knows, for the architecture
the image is built for, and the report of `deploy_sessions.py` had to either leave
it out or estimate it. The estimate is what the pool design called its Q3, and an
estimate printed beside a measured ceiling reads as a measurement.

## How it is measured

Each image that names its slot type completely carries, behind the off-by-default
cargo feature `slot-bytes-probe`, one `static WZ_SESSION_SLOT_BYTES: [u8; N]` with
`N` the slot's size. This script builds the image with that feature, for the target
and with the build values the S8 gate already builds it with (`no_allocator_link_gate`
owns that table, and this module reads it rather than restating it), and reads the
SIZE of that symbol with `nm -S`. A symbol's size is a value every `nm` prints, so no
output of the compiler has to be parsed and no nightly flag is needed.

An image generic over its clock and entropy types (the acceptor e2e) names no slot
type and has no probe; its number would be a different one.

## What is held

`deploy/session_slot_bytes.json` records the measured number per image. `--check`
rebuilds, re-reads and fails where the record differs: a type that grew, a toolchain
whose layout moved, or an image that stopped carrying the probe. The file is
regenerated with `--write`, in the commit that moves the number, so the change is
visible in review. `deploy_sessions.py` reads the file for a machine that names its
image (`session_pool.typed_slot_image`) and reports the bytes and the headroom
against the ceiling, and refuses a ceiling the measurement exceeds.

The recorded `rustc` is information, not a comparison: a toolchain bump that moves
the number is reported by `--check` as the number moving, which is the right place
to learn it.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import no_allocator_link_gate as gate  # noqa: E402

ROOT = gate.REPO_ROOT
RECORD = ROOT / "deploy" / "session_slot_bytes.json"
PROBE_FEATURE = "slot-bytes-probe"
PROBE_SYMBOL = "WZ_SESSION_SLOT_BYTES"
SCHEMA = 1

# (record key, the S8 gate's image row, the build label of that row). The build
# itself (target, lwIP port, build values, feature set) is the gate's row, so the
# slot is measured in the build the no-allocator proof judges.
SUBJECTS: tuple[tuple[str, str, str], ...] = (
    ("mcu-admin-node", "mcu-admin-node-fixed", "mps2-fixed"),
    ("zephyr-admin-node", "zephyr-admin-node-fixed", "cyt4bf-lwip-fixed"),
)

ABOUT = (
    "The bytes ONE typed session slot takes in each image, as the compiler lays it "
    "out for the target, read from the size of the WZ_SESSION_SLOT_BYTES probe symbol "
    "(scripts/lib/session_slot_bytes.py; build the image with the cargo feature "
    "slot-bytes-probe). Regenerate with `session_slot_bytes.py --write` in the commit "
    "that moves a number. `rustc` is information, not compared."
)


def symbol_size(nm_text: str, symbol: str) -> int | None:
    """The size `nm -S` prints for `symbol`, or None.

    A line of `nm -S -p` is `address size type name` (the size and address in hex).
    The name must match EXACTLY: a symbol that merely contains the probe's name is
    some other symbol. A probe present twice (two copies in one artifact) is not a
    measurement, so it is None here and the caller says why from `symbol_sizes`.
    """
    found = symbol_sizes(nm_text, symbol)
    return found[0] if len(found) == 1 else None


def symbol_sizes(nm_text: str, symbol: str) -> list[int]:
    out: list[int] = []
    for line in nm_text.splitlines():
        parts = line.split()
        if len(parts) != 4 or parts[3] != symbol:
            continue
        try:
            out.append(int(parts[1], 16))
        except ValueError:
            continue
    return out


def rustc_version() -> str:
    proc = subprocess.run(["rustc", "--version"], capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def measure(key: str) -> tuple[str, int]:
    """Build the image with the probe and return `(target, slot bytes)`."""
    row = {k: (img, lab) for k, img, lab in SUBJECTS}.get(key)
    if row is None:
        raise SystemExit(
            f"session_slot_bytes: no subject `{key}` (the subjects are "
            f"{', '.join(k for k, _, _ in SUBJECTS)})"
        )
    image_name, label = row
    image = gate.IMAGES[image_name]
    build = next((b for b in image.builds if b.label == label), None)
    if build is None:
        raise SystemExit(
            f"session_slot_bytes: the gate's row `{image_name}` has no build labelled `{label}`"
        )
    probed = replace(build, features=build.features + (PROBE_FEATURE,))
    cmd, env = gate.build_command(image, probed, False)
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-4000:])
        raise SystemExit(
            f"session_slot_bytes: `{key}` does not build with the probe (rc={proc.returncode})"
        )
    units, executable, _ = gate.cargo_units(proc.stdout, probed.target)
    artifact = executable
    if image.kind == "staticlib":
        libs = [u.filename for u in units if u.filename.endswith(".a")]
        artifact = libs[-1] if libs else None
    if not artifact or not Path(artifact).exists():
        raise SystemExit(f"session_slot_bytes: no linked artifact for `{key}`")
    nm, why = gate.resolve_nm()
    if nm is None:
        raise SystemExit(f"session_slot_bytes: {why} (cannot read the probe)")
    read = subprocess.run([nm, "-S", "-p", artifact], capture_output=True, text=True)
    if read.returncode != 0:
        raise SystemExit(f"session_slot_bytes: nm failed on `{key}`: {read.stderr[-400:]}")
    sizes = symbol_sizes(read.stdout, PROBE_SYMBOL)
    if len(sizes) != 1:
        raise SystemExit(
            f"session_slot_bytes: `{key}` carries {len(sizes)} symbol(s) named "
            f"{PROBE_SYMBOL}, expected exactly one (does the image still declare the "
            f"probe behind the `{PROBE_FEATURE}` feature?)"
        )
    return probed.target, sizes[0]


def load_record(path: Path = RECORD) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise SystemExit(f"session_slot_bytes: cannot read {path}: {exc}")
    if data.get("schema") != SCHEMA or not isinstance(data.get("images"), dict):
        raise SystemExit(f"session_slot_bytes: {path} is not a schema {SCHEMA} record")
    return data


def render(images: dict[str, dict], rustc: str) -> str:
    return (
        json.dumps(
            {"about": ABOUT, "schema": SCHEMA, "rustc": rustc, "images": images},
            indent=2,
        )
        + "\n"
    )


def drift(recorded: dict[str, dict], measured: dict[str, tuple[str, int]]) -> list[str]:
    """Every way the record and the measurement disagree, by name."""
    out: list[str] = []
    for key in sorted(set(recorded) | set(measured)):
        if key not in measured:
            out.append(f"{key}: the record names an image this script no longer measures")
        elif key not in recorded:
            out.append(f"{key}: measured at {measured[key][1]} and absent from the record")
        else:
            want, (target, got) = recorded[key], measured[key]
            if want.get("target") != target:
                out.append(
                    f"{key}: recorded for target {want.get('target')}, measured for {target}"
                )
            if want.get("slot_bytes") != got:
                out.append(f"{key}: recorded {want.get('slot_bytes')} bytes, measured {got}")
    return out


def entry(key: str, target: str, size: int) -> dict:
    image_name, label = next((i, lab) for k, i, lab in SUBJECTS if k == key)
    return {"gate_image": image_name, "build": label, "target": target, "slot_bytes": size}


def run_subjects(only: str | None) -> dict[str, tuple[str, int]]:
    keys = [k for k, _, _ in SUBJECTS if only in (None, k)]
    if not keys:
        raise SystemExit(f"session_slot_bytes: no subject `{only}`")
    return {k: measure(k) for k in keys}


def cmd_check(only: str | None) -> int:
    recorded = load_record()["images"]
    measured = run_subjects(only)
    if only is not None:
        recorded = {k: v for k, v in recorded.items() if k == only}
    found = drift(recorded, measured)
    if found:
        print("session-slot-bytes: FAIL -- the record and the measurement differ:", file=sys.stderr)
        for line in found:
            print(f"  - {line}", file=sys.stderr)
        print(
            "  regenerate with `python3 scripts/lib/session_slot_bytes.py --write` in the "
            "commit that moves the number",
            file=sys.stderr,
        )
        return 1
    for key, (target, size) in sorted(measured.items()):
        print(
            f"  session-slot-bytes: {key} [{target}] one typed slot = {size} bytes, "
            f"equal to the record"
        )
    return 0


def cmd_write() -> int:
    measured = run_subjects(None)
    images = {k: entry(k, t, s) for k, (t, s) in measured.items()}
    rustc = rustc_version()
    RECORD.write_text(render(images, rustc))
    sizes = ", ".join(f"{k}={s}[{t}]" for k, (t, s) in sorted(measured.items()))
    print(f"session-slot-bytes: wrote {RECORD.relative_to(ROOT)} ({sizes}) with {rustc}")
    return 0


def cmd_list() -> int:
    for key, image_name, label in SUBJECTS:
        image = gate.IMAGES[image_name]
        build = next(b for b in image.builds if b.label == label)
        print(key, build.target)
    return 0


def selftest() -> int:
    failures: list[str] = []

    def expect(label: str, cond: bool) -> None:
        print(f"  {'ok  ' if cond else 'FAIL'} {label}")
        if not cond:
            failures.append(label)

    nm = (
        "20000000 00000718 B WZ_SESSION_SLOT_BYTES\n"
        "20000718 00000004 B OTHER\n"
        "20000720 00000718 B NOT_WZ_SESSION_SLOT_BYTES\n"
        "00000800 t local_symbol\n"
    )
    expect(
        "the probe's size is read in hex from the exact name",
        symbol_size(nm, PROBE_SYMBOL) == 0x718,
    )
    expect(
        "a name that merely contains the probe's is another symbol",
        symbol_sizes(nm, "SLOT_BYTES") == [],
    )
    expect(
        "an absent probe is None", symbol_size("20000000 00000004 B X\n", PROBE_SYMBOL) is None
    )
    twice = nm + "20001000 00000010 B WZ_SESSION_SLOT_BYTES\n"
    expect("a probe present twice is not a measurement", symbol_size(twice, PROBE_SYMBOL) is None)
    expect(
        "a size that is not hex is skipped, not guessed",
        symbol_sizes("20000000 zz B WZ_SESSION_SLOT_BYTES\n", PROBE_SYMBOL) == [],
    )

    rec = {"a": {"target": "t1", "slot_bytes": 10}, "b": {"target": "t2", "slot_bytes": 20}}
    expect("an equal record has no drift", drift(rec, {"a": ("t1", 10), "b": ("t2", 20)}) == [])
    found = drift(rec, {"a": ("t1", 11), "b": ("t2", 20)})
    expect(
        "a number that moved is named with both values",
        len(found) == 1 and "recorded 10 bytes, measured 11" in found[0],
    )
    found = drift(rec, {"a": ("t9", 10), "b": ("t2", 20)})
    expect("a target that moved is named", len(found) == 1 and "target" in found[0])
    found = drift(rec, {"a": ("t1", 10)})
    expect(
        "a recorded image no longer measured is named",
        len(found) == 1 and "no longer measures" in found[0],
    )
    found = drift({"a": rec["a"]}, {"a": ("t1", 10), "b": ("t2", 20)})
    expect(
        "a measured image absent from the record is named",
        len(found) == 1 and "absent from the record" in found[0],
    )
    text = render({"a": entry("mcu-admin-node", "thumbv7m-none-eabi", 7)}, "rustc 1")
    expect(
        "the record renders as the JSON it is read back from",
        json.loads(text)["images"]["a"]["slot_bytes"] == 7 and text.endswith("\n"),
    )
    expect(
        "every subject names a gate row and a build that exist",
        all(any(b.label == lab for b in gate.IMAGES[img].builds) for _, img, lab in SUBJECTS),
    )
    print(f"session-slot-bytes selftest: {'FAIL' if failures else 'OK'} ({len(failures)} failing)")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="the measured size of one typed session slot")
    parser.add_argument("--check", action="store_true", help="rebuild and hold the record equal")
    parser.add_argument("--write", action="store_true", help="rebuild and rewrite the record")
    parser.add_argument("--list", action="store_true", help="print `key target` per subject")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--image", help="with --check: only this record key")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.list:
        return cmd_list()
    if args.write:
        return cmd_write()
    if args.check:
        return cmd_check(args.image)
    parser.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
