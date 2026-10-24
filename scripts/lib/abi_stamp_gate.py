#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""The ABI stamp of every shipped artifact, read from the BUILT artifact and held to a pin.

`docs/target-build-contract.md` T6: each artifact carries `{family, revision, layout}` as an ELF
note (`wz-abi-stamp`), so a tool describing it for a device it cannot run on reads the number from
the file. This gate holds that note.

## What is read, and from where

The note comes out of the artifact's BYTES (`elf_facts.read_abi_stamp`). A gate that read the
`revision` constant out of the Rust source would pin the text an author had just edited; the
number a deployment tool receives is the one in the file, so the file is what is judged.

## What is pinned

`EXPECTED` is the declared half, and it is deliberately written HERE and not derived: a pin that
followed the artifact could not fail. A family's revision moves when an author edits the constant
and this table in one commit, which is the whole mechanism (`capi_abi_pin.py` and
`capi_c_abi_pin.py` argue the same for their symbol sets). It pins three things for the default
build: the family's revision, the exact set of layout keys, and each key's value.

## What must agree

* every profile the lane builds (`debug` and `release`) must carry the SAME stamp: a stamp present
  or different in one profile is a claim about that build only, and `lto = "thin"` runs in release;
* a stamp must survive `strip`, which the gate runs on a copy of each artifact: the note is what a
  consumer reads from a binary it ships stripped;
* for `capi-c`, whose library has a door that reports the same number (`wz_capi_c_abi_version`),
  the stamp must equal the number the loaded library returns, so the two ways of asking cannot
  drift apart.

`--selftest` drives every FAIL path through a synthetic ELF and a clean control first: a gate that
had started passing everything cannot be mistaken for artifacts that are in order.
"""

from __future__ import annotations

import ctypes
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import elf_facts  # noqa: E402

# The pinned stamp of each family's DEFAULT build. Edit with the family's revision constant, in the
# same commit:
#   capi-pico        crates/wz-capi-pico/src/revision.rs      WZ_CAPI_PICO_ABI_REVISION
#   capi-c           crates/wz-capi-c/src/abi.rs              WZ_CAPI_C_ABI_REVISION
#   ap-demo-surface  crates/wz-ap-demo/src/surface.rs         SURFACE_REVISION
EXPECTED = {
    "capi-pico": {
        "revision": 1,
        "layout": {
            "multi_thread": True,
            "unstable_api": True,
            "local_subscriber": False,
            "local_queryable": False,
        },
    },
    "capi-c": {
        "revision": 6,
        "layout": {"unstable_api": True, "shared_memory": False},
    },
    "ap-demo-surface": {"revision": 1, "layout": {}},
}

REQUIRED_PROFILES = {"debug", "release"}

# The families whose library answers the same question through a door.
DOORS = {"capi-c": "wz_capi_c_abi_version"}


class Fatal(Exception):
    pass


def profile_of(path: pathlib.Path) -> str:
    """The cargo profile an artifact was built under, from its place under `target/`."""
    parts = path.parts
    if "target" in parts:
        i = len(parts) - 1 - parts[::-1].index("target")
        if i + 2 < len(parts):
            return parts[i + 1]
    raise Fatal(
        f"cannot tell which cargo profile {path} was built under: it is not under <...>/target/<profile>/"
    )


def stamp_findings(family: str, stamp: dict) -> list[str]:
    """What is wrong with one stamp, against the pin of the family it should be."""
    if family not in EXPECTED:
        return [f"{family}: no such family is pinned (known: {', '.join(sorted(EXPECTED))})"]
    want = EXPECTED[family]
    out = []
    if stamp["family"] != family:
        out.append(f"the stamp's family is {stamp['family']!r}, the artifact is a {family!r}")
    if stamp["revision"] != want["revision"]:
        out.append(
            f"{family} revision is {stamp['revision']} in the artifact and pinned at {want['revision']}"
        )
    have, pinned = stamp["layout"], want["layout"]
    for key in sorted(set(have) - set(pinned)):
        out.append(f"{family} layout has the key {key!r}, which the pin does not")
    for key in sorted(set(pinned) - set(have)):
        out.append(f"{family} layout lacks the pinned key {key!r}")
    for key in sorted(set(have) & set(pinned)):
        if have[key] != pinned[key]:
            out.append(f"{family} layout {key} is {have[key]} in the artifact and pinned at {pinned[key]}")
    return out


def profile_findings(family: str, by_profile: dict[str, dict]) -> list[str]:
    """What is wrong across profiles: a missing profile, or two that disagree."""
    out = []
    for profile in sorted(REQUIRED_PROFILES - set(by_profile)):
        out.append(f"{family}: no {profile} artifact was given; one profile is not a comparison")
    stamps = {p: s for p, s in by_profile.items()}
    first = next(iter(sorted(stamps)), None)
    for profile in sorted(stamps):
        if first is not None and stamps[profile] != stamps[first]:
            out.append(
                f"{family}: the {profile} stamp {stamps[profile]} differs from the {first} stamp {stamps[first]}"
            )
    return out


def door_revision(library: pathlib.Path, symbol: str) -> int:
    """The number the loaded library returns from its own door."""
    try:
        lib = ctypes.CDLL(str(library))
        fn = getattr(lib, symbol)
    except (OSError, AttributeError) as err:
        raise Fatal(f"cannot call {symbol} in {library}: {err}") from err
    fn.restype = ctypes.c_int32
    fn.argtypes = []
    return int(fn())


def survives_strip(path: pathlib.Path) -> dict:
    """The stamp of a stripped copy of `path`."""
    strip = shutil.which("strip")
    if strip is None:
        raise Fatal("strip is absent, so survival of the stamp through stripping cannot be read; "
                    "a gate that cannot reach its input must not report green")
    with tempfile.TemporaryDirectory(prefix="wz-abi-stamp-") as work:
        copy = pathlib.Path(work) / path.name
        shutil.copyfile(path, copy)
        run = subprocess.run([strip, str(copy)], capture_output=True, text=True, check=False)
        if run.returncode != 0:
            raise Fatal(f"strip failed on a copy of {path}: {run.stderr.strip()}")
        try:
            return elf_facts.read_abi_stamp_file(str(copy))
        except elf_facts.ElfError as err:
            raise Fatal(f"{path} loses its stamp when stripped: {err}") from err


def run(items: list[tuple[str, pathlib.Path]], call_doors: bool) -> int:
    by_family: dict[str, dict[str, dict]] = {}
    findings: list[str] = []
    for family, path in items:
        profile = profile_of(path)
        try:
            stamp = elf_facts.read_abi_stamp_file(str(path))
        except (elf_facts.ElfError, OSError) as err:
            findings.append(f"{family} ({path}): {err}")
            continue
        if profile in by_family.setdefault(family, {}):
            raise Fatal(f"{family}: two artifacts were given for the {profile} profile")
        by_family[family][profile] = stamp
        findings += [f"{path}: {f}" for f in stamp_findings(family, stamp)]
        try:
            stripped = survives_strip(path)
        except Fatal as err:
            findings.append(str(err))
        else:
            if stripped != stamp:
                findings.append(f"{path}: the stripped copy carries a different stamp {stripped}")
        if call_doors and family in DOORS:
            called = door_revision(path, DOORS[family])
            if called != stamp["revision"]:
                findings.append(
                    f"{path}: {DOORS[family]}() returns {called} and the stamp says {stamp['revision']}"
                )
    for family, by_profile in sorted(by_family.items()):
        findings += profile_findings(family, by_profile)
    for family in sorted(EXPECTED):
        if family not in by_family and not any(f.startswith(f"{family} (") for f in findings):
            findings.append(f"{family}: no artifact was given")
    if findings:
        for line in findings:
            print(f"  abi-stamp FAIL: {line}", file=sys.stderr)
        return 1
    for family, by_profile in sorted(by_family.items()):
        stamp = by_profile[sorted(by_profile)[0]]
        print(f"  abi-stamp OK: {family} revision {stamp['revision']} layout {stamp['layout']} "
              f"({', '.join(sorted(by_profile))})")
    return 0


# ---------------------------------------------------------------------------
# Self-test: a synthetic ELF, so every FAIL path is driven by a file whose defect is known.
# ---------------------------------------------------------------------------


def mini_elf(notes: list[tuple[str, str, int, bytes]], cls: int = 64, order: str = "<") -> bytes:
    """An ELF with no segments and one note section per entry: (section, owner, type, desc)."""
    def note(owner: str, kind: int, desc: bytes) -> bytes:
        name = owner.encode() + b"\x00"
        pad = lambda b: b + b"\x00" * (-len(b) % 4)  # noqa: E731
        return struct.pack(order + "III", len(name), len(desc), kind) + pad(name) + pad(desc)

    names = b"\x00"
    shstr_off = {}
    for section, *_ in notes:
        shstr_off[section] = len(names)
        names += section.encode() + b"\x00"
    shstr_off[".shstrtab"] = len(names)
    names += b".shstrtab\x00"
    header_size = 64 if cls == 64 else 52
    body = b""
    placed = []
    for section, owner, kind, desc in notes:
        blob = note(owner, kind, desc)
        placed.append((section, header_size + len(body), len(blob)))
        body += blob
    names_off = header_size + len(body)
    body += names
    shoff = header_size + len(body)
    shdr = order + ("IIQQQQIIQQ" if cls == 64 else "IIIIIIIIII")
    table = struct.pack(shdr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for section, off, size in placed:
        table += struct.pack(shdr, shstr_off[section], elf_facts.SHT_NOTE, 2, 0, off, size, 0, 0, 4, 0)
    table += struct.pack(shdr, shstr_off[".shstrtab"], 3, 0, 0, names_off, len(names), 0, 0, 1, 0)
    count = len(placed) + 2
    ident = b"\x7fELF" + bytes([1 if cls == 32 else 2, 1 if order == "<" else 2, 1]) + b"\x00" * 9
    if cls == 64:
        head = ident + struct.pack(order + "HHIQQQIHHHHHH", 3, 183, 1, 0, 0, shoff, 0, 64, 0, 0, 64, count, count - 1)
    else:
        head = ident + struct.pack(order + "HHIIIIIHHHHHH", 3, 40, 1, 0, 0, shoff, 0, 52, 0, 0, 40, count, count - 1)
    assert len(head) == header_size, (len(head), header_size)
    return head + body + table


def stamp_bytes(family: str, revision, layout: dict, schema: int = 1, extra: dict | None = None) -> bytes:
    import json

    obj = {"schema": schema, "family": family, "revision": revision, "layout": layout}
    obj.update(extra or {})
    return json.dumps(obj, separators=(",", ":")).encode() + b"\x00"


def selftest() -> int:
    def expect(label: str, condition: bool) -> None:
        if not condition:
            raise Fatal(f"selftest: {label}")

    good = EXPECTED["capi-pico"]
    clean = stamp_bytes("capi-pico", good["revision"], good["layout"])
    elf = mini_elf([(elf_facts.STAMP_SECTION, "wz", 1, clean)])

    # The control: a clean stamp in every ELF shape reads back and raises no finding.
    for cls, order in [(64, "<"), (32, "<"), (64, ">"), (32, ">")]:
        data = mini_elf([(elf_facts.STAMP_SECTION, "wz", 1, clean)], cls, order)
        stamp = elf_facts.read_abi_stamp(data)
        expect(f"a clean stamp was misread in ELF{cls} {order!r}", stamp["revision"] == good["revision"])
        expect("the clean control raised a finding", stamp_findings("capi-pico", stamp) == [])

    def reads(data: bytes) -> bool:
        try:
            elf_facts.read_abi_stamp(data)
        except elf_facts.ElfError:
            return False
        return True

    s = elf_facts.STAMP_SECTION
    expect("a file with no note was read as a stamp", not reads(mini_elf([("other", "x", 1, b"abcd")])))
    expect("two stamps were read as one", not reads(mini_elf([(s, "wz", 1, clean), (s, "wz", 1, clean)])))
    expect("a stamp in the wrong section was accepted", not reads(mini_elf([("other", "wz", 1, clean)])))
    expect("a note of another owner was read as a stamp", not reads(mini_elf([(s, "gnu", 1, clean)])))
    expect("a note of another type was read as a stamp", not reads(mini_elf([(s, "wz", 2, clean)])))
    expect("a stamp with no NUL was accepted", not reads(mini_elf([(s, "wz", 1, clean[:-1])])))
    expect("schema 2 was accepted", not reads(mini_elf([(s, "wz", 1, stamp_bytes("capi-pico", 1, {}, schema=2))])))
    expect("a boolean revision was accepted",
           not reads(mini_elf([(s, "wz", 1, stamp_bytes("capi-pico", True, {}))])))
    expect("a negative revision was accepted",
           not reads(mini_elf([(s, "wz", 1, stamp_bytes("capi-pico", -1, {}))])))
    expect("a layout of non-booleans was accepted",
           not reads(mini_elf([(s, "wz", 1, stamp_bytes("capi-pico", 1, {"multi_thread": 1}))])))
    expect("an extra key was accepted",
           not reads(mini_elf([(s, "wz", 1, stamp_bytes("capi-pico", 1, {}, extra={"more": 1}))])))
    expect("a stamp that is not JSON was accepted", not reads(mini_elf([(s, "wz", 1, b"{nope\x00")])))
    expect("a truncated file was read", not reads(elf[: len(elf) // 2]))
    expect("a file that is not ELF was read", not reads(b"not an elf file at all, sixteen+ bytes"))
    expect("an empty file was read", not reads(b""))

    # The pin: each of the three things it holds fails alone, and names the family.
    def findings_of(family: str, revision, layout: dict) -> list[str]:
        return stamp_findings(family, {"schema": 1, "family": family, "revision": revision, "layout": layout})

    layout = dict(good["layout"])
    expect("a moved revision was not reported",
           any("revision" in f for f in findings_of("capi-pico", good["revision"] + 1, layout)))
    expect("an extra layout key was not reported",
           any("extra_switch" in f for f in findings_of("capi-pico", good["revision"], {**layout, "extra_switch": True})))
    missing = {k: v for k, v in layout.items() if k != "multi_thread"}
    expect("a missing layout key was not reported",
           any("multi_thread" in f for f in findings_of("capi-pico", good["revision"], missing)))
    flipped = {**layout, "unstable_api": not layout["unstable_api"]}
    expect("a flipped layout value was not reported",
           any("unstable_api" in f for f in findings_of("capi-pico", good["revision"], flipped)))
    expect("a stamp of the wrong family was not reported",
           any("family" in f for f in stamp_findings("capi-c", {"schema": 1, "family": "capi-pico",
                                                                 "revision": 6, "layout": EXPECTED["capi-c"]["layout"]})))
    expect("an unpinned family was not reported", any("no such family" in f for f in findings_of("nope", 1, {})))

    # The profile axis: one profile is not a comparison; two that disagree are reported.
    a = {"schema": 1, "family": "capi-c", "revision": 6, "layout": {}}
    b = {**a, "revision": 7}
    expect("two agreeing profiles were reported",
           profile_findings("capi-c", {"debug": a, "release": dict(a)}) == [])
    expect("two disagreeing profiles were not reported",
           any("differs" in f for f in profile_findings("capi-c", {"debug": a, "release": b})))
    expect("a single profile was accepted",
           any("release" in f for f in profile_findings("capi-c", {"debug": a})))
    expect("the profile reader misread a target path",
           profile_of(pathlib.Path("crates/target/release/libwz_capi_c.so")) == "release")
    for bad in ["libwz_capi_c.so", "crates/target/libwz_capi_c.so", "/tmp/x/lib.so"]:
        try:
            profile_of(pathlib.Path(bad))
        except Fatal:
            continue
        raise Fatal(f"selftest: a non-profile path was accepted: {bad}")

    # The pin is not vacuous, and every family has a door entry or none.
    expect("the pin is empty and agrees with anything", len(EXPECTED) == 3)
    expect("a door is named for a family that is not pinned", set(DOORS) <= set(EXPECTED))
    expect("a pinned revision is not a non-negative integer",
           all(isinstance(v["revision"], int) and v["revision"] >= 0 for v in EXPECTED.values()))

    print("abi-stamp-gate: selftest OK")
    return 0


if __name__ == "__main__":
    argv = sys.argv[1:]
    try:
        if "--selftest" in argv:
            sys.exit(selftest())
        doors = "--call-doors" in argv
        pairs = [a for a in argv if a != "--call-doors"]
        if not pairs or not all("=" in a for a in pairs):
            print(
                "usage: abi_stamp_gate.py [--call-doors] FAMILY=PATH... | --selftest\n"
                f"  families: {', '.join(sorted(EXPECTED))}; one path per cargo profile "
                f"({', '.join(sorted(REQUIRED_PROFILES))} are required)",
                file=sys.stderr,
            )
            sys.exit(2)
        sys.exit(run([(a.split("=", 1)[0], pathlib.Path(a.split("=", 1)[1])) for a in pairs], doors))
    except Fatal as e:
        print(f"abi-stamp-gate: FAIL -- {e}", file=sys.stderr)
        sys.exit(1)
