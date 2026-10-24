#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""Facts read from an ELF file's bytes, without running it.

`docs/target-build-contract.md` T4: a tool that describes an artifact for a device it is not built
on cannot call the artifact, so every fact it reports is read from the file. This module is that
reader, in the standard library only, so the same code serves the gate that holds the facts
(`abi_stamp_gate.py`) and the entry that records them (`package`, step 3): two readers of one
format would be the second copy this file exists to prevent.

It reads the section headers and the notes in the note sections, for ELF32 and ELF64, either byte
order. Step 1 needs the ABI stamp only; the dynamic section (NEEDED, SONAME, RUNPATH) and the
version needs are step 3's, and arrive in this module rather than beside it.

It refuses what it cannot read. A short file, a header that points outside the file and a note
that overruns its section are each an `ElfError` naming what was malformed, never an empty answer:
a reader that returned "no stamp" for a truncated file would let a damaged artifact pass for one
that has none.
"""

from __future__ import annotations

import json
import struct

SHT_NOTE = 7

STAMP_SECTION = ".note.wz.abi"
STAMP_OWNER = "wz"
STAMP_NOTE_TYPE = 1
STAMP_SCHEMA = 1
STAMP_KEYS = {"schema", "family", "revision", "layout"}


class ElfError(Exception):
    """The file is not an ELF this reader can read, or is malformed where it was read."""


class Section:
    __slots__ = ("name", "kind", "offset", "size")

    def __init__(self, name: str, kind: int, offset: int, size: int) -> None:
        self.name = name
        self.kind = kind
        self.offset = offset
        self.size = size


class Note:
    __slots__ = ("section", "owner", "kind", "desc")

    def __init__(self, section: str, owner: str, kind: int, desc: bytes) -> None:
        self.section = section
        self.owner = owner
        self.kind = kind
        self.desc = desc


def _span(data: bytes, offset: int, size: int, what: str) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ElfError(f"{what} lies outside the file (offset {offset}, size {size}, file {len(data)} bytes)")
    return data[offset : offset + size]


def _byte_order(data: bytes) -> str:
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file")
    if data[4] not in (1, 2):
        raise ElfError(f"unknown ELF class {data[4]}")
    if data[5] not in (1, 2):
        raise ElfError(f"unknown ELF data encoding {data[5]}")
    return "<" if data[5] == 1 else ">"


def sections(data: bytes) -> list[Section]:
    """Every section of the file, named."""
    end = _byte_order(data)
    if data[4] == 2:
        head = _span(data, 0, 64, "the ELF header")
        (shoff,) = struct.unpack_from(end + "Q", head, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", head, 0x3A)
        shdr = end + "IIQQQQ"
    else:
        head = _span(data, 0, 52, "the ELF header")
        (shoff,) = struct.unpack_from(end + "I", head, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", head, 0x2E)
        shdr = end + "IIIIII"
    if shnum == 0:
        return []
    need = struct.calcsize(shdr)
    if shentsize < need:
        raise ElfError(f"section header entries are {shentsize} bytes, fewer than the {need} the format has")
    raw = []
    for i in range(shnum):
        entry = _span(data, shoff + i * shentsize, need, f"section header {i}")
        fields = struct.unpack_from(shdr, entry, 0)
        # name, type, flags, addr, offset, size
        raw.append((fields[0], fields[1], fields[4], fields[5]))
    if shstrndx >= len(raw):
        raise ElfError("the section name table index is outside the section headers")
    names = _span(data, raw[shstrndx][2], raw[shstrndx][3], "the section name table")
    out = []
    for name_off, kind, offset, size in raw:
        stop = names.find(b"\x00", name_off)
        if name_off >= len(names) or stop < 0:
            raise ElfError("a section name is outside the name table")
        out.append(Section(names[name_off:stop].decode("utf-8", "replace"), kind, offset, size))
    return out


def notes(data: bytes) -> list[Note]:
    """Every note of every note section."""
    end = _byte_order(data)
    found = []
    for section in sections(data):
        if section.kind != SHT_NOTE:
            continue
        body = _span(data, section.offset, section.size, f"section {section.name}")
        pos = 0
        while pos < len(body):
            if pos + 12 > len(body):
                raise ElfError(f"a note in {section.name} is cut short (its header does not fit)")
            namesz, descsz, kind = struct.unpack_from(end + "III", body, pos)
            pos += 12
            name_end = pos + (namesz + 3) // 4 * 4
            desc_end = name_end + (descsz + 3) // 4 * 4
            if desc_end > len(body):
                raise ElfError(f"a note in {section.name} overruns its section")
            owner = body[pos : pos + namesz].rstrip(b"\x00").decode("utf-8", "replace")
            found.append(Note(section.name, owner, kind, bytes(body[name_end : name_end + descsz])))
            pos = desc_end
    return found


def read_abi_stamp(data: bytes) -> dict:
    """The one ABI stamp the file carries, parsed and checked against the stamp's own format.

    Exactly one note of owner `wz` and type 1 must exist, in the section the writer uses; none and
    two are both errors. The object must have exactly the four keys of schema 1.
    """
    stamps = [n for n in notes(data) if n.owner == STAMP_OWNER and n.kind == STAMP_NOTE_TYPE]
    if not stamps:
        raise ElfError("the file carries no ABI stamp")
    if len(stamps) > 1:
        raise ElfError(f"the file carries {len(stamps)} ABI stamps; an artifact has one")
    note = stamps[0]
    if note.section != STAMP_SECTION:
        raise ElfError(f"the ABI stamp is in section {note.section}, not {STAMP_SECTION}")
    if not note.desc.endswith(b"\x00"):
        raise ElfError("the ABI stamp is not NUL-terminated")
    try:
        stamp = json.loads(note.desc[:-1].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise ElfError(f"the ABI stamp is not JSON: {err}") from err
    if not isinstance(stamp, dict) or set(stamp) != STAMP_KEYS:
        raise ElfError(f"the ABI stamp does not have exactly the keys {sorted(STAMP_KEYS)}")
    if stamp["schema"] != STAMP_SCHEMA:
        raise ElfError(f"the ABI stamp is schema {stamp['schema']!r}; this reader reads {STAMP_SCHEMA}")
    if not isinstance(stamp["family"], str) or not stamp["family"]:
        raise ElfError("the ABI stamp's family is not a non-empty string")
    if isinstance(stamp["revision"], bool) or not isinstance(stamp["revision"], int) or stamp["revision"] < 0:
        raise ElfError("the ABI stamp's revision is not a non-negative integer")
    layout = stamp["layout"]
    if not isinstance(layout, dict) or not all(isinstance(v, bool) for v in layout.values()):
        raise ElfError("the ABI stamp's layout is not an object of booleans")
    return stamp


def read_abi_stamp_file(path: str) -> dict:
    with open(path, "rb") as handle:
        return read_abi_stamp(handle.read())
