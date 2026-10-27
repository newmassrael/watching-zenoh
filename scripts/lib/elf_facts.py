#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3521 (no register item) -- facts read from an ELF file's bytes, without running it.

`docs/target-build-contract.md` T4: a tool that describes an artifact for a device it is not built
on cannot call the artifact, so every fact it reports is read from the file. This module is that
reader, in the standard library only, so the same code serves the gate that holds the facts
(`abi_stamp_gate.py`, `manifest_gate.py`) and the entry that records them (`wz_package.py`): two
readers of one format would be the second copy this file exists to prevent.

It reads ELF32 and ELF64, either byte order, from the section headers (a stripped file keeps them):

  * the notes: the ABI stamp and the facts note (`wz-abi-stamp`) and Android's identification note;
  * the dynamic section: NEEDED, SONAME, RUNPATH, RPATH, and the interpreter;
  * the version needs: the symbol-version tags an artifact asks the C library for, and the highest
    glibc one.

It refuses what it cannot read. A short file, a header that points outside the file and a note that
overruns its section are each an `ElfError` naming what was malformed, never an empty answer: a
reader that returned "no stamp" for a truncated file would let a damaged artifact pass for one that
has none.

`build_test_elf` makes a small ELF with exactly the sections a test asks for, so every refusal of
the gates that use this module is driven by a file whose defect is known.
"""

from __future__ import annotations

import json
import struct
import sys

SHT_NOTE = 7
SHT_DYNAMIC = 6
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_GNU_VERNEED = 0x6FFFFFFE
SHT_DYNSYM = 11
SHT_RELA = 4
SHT_REL = 9
SHN_UNDEF = 0

DT_NULL, DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH = 0, 1, 14, 15, 29

STAMP_SECTION = ".note.wz.abi"
FACTS_SECTION = ".note.wz.facts"
STAMP_OWNER = "wz"
STAMP_NOTE_TYPE = 1
FACTS_NOTE_TYPE = 2
STAMP_SCHEMA = 1
STAMP_KEYS = {"schema", "family", "revision", "layout"}
FACTS_KEYS = {"schema", "lists"}

# e_machine values this tree builds for, by the name the manifest uses. Another value is reported
# as `unknown-<n>` rather than guessed.
MACHINES = {62: "x86_64", 183: "aarch64", 40: "arm", 243: "riscv", 3: "x86", 164: "hexagon"}

ANDROID_NOTE_SECTION = ".note.android.ident"
ANDROID_NOTE_OWNER = "Android"
ANDROID_NOTE_TYPE = 1


class ElfError(Exception):
    """The file is not an ELF this reader can read, or is malformed where it was read."""


class Section:
    __slots__ = ("name", "kind", "offset", "size", "link")

    def __init__(self, name: str, kind: int, offset: int, size: int, link: int) -> None:
        self.name = name
        self.kind = kind
        self.offset = offset
        self.size = size
        self.link = link


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
        shdr = end + "IIQQQQI"
    else:
        head = _span(data, 0, 52, "the ELF header")
        (shoff,) = struct.unpack_from(end + "I", head, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", head, 0x2E)
        shdr = end + "IIIIIII"
    if shnum == 0:
        return []
    need = struct.calcsize(shdr)
    if shentsize < need:
        raise ElfError(f"section header entries are {shentsize} bytes, fewer than the {need} the format has")
    raw = []
    for i in range(shnum):
        entry = _span(data, shoff + i * shentsize, need, f"section header {i}")
        fields = struct.unpack_from(shdr, entry, 0)
        # name, type, flags, addr, offset, size, link
        raw.append((fields[0], fields[1], fields[4], fields[5], fields[6]))
    if shstrndx >= len(raw):
        raise ElfError("the section name table index is outside the section headers")
    names = _span(data, raw[shstrndx][2], raw[shstrndx][3], "the section name table")
    out = []
    for name_off, kind, offset, size, link in raw:
        stop = names.find(b"\x00", name_off)
        if name_off >= len(names) or stop < 0:
            raise ElfError("a section name is outside the name table")
        out.append(Section(names[name_off:stop].decode("utf-8", "replace"), kind, offset, size, link))
    return out


def section_bytes(data: bytes, section: Section) -> bytes:
    return _span(data, section.offset, section.size, f"section {section.name}")


def notes(data: bytes) -> list[Note]:
    """Every note of every note section."""
    end = _byte_order(data)
    found = []
    for section in sections(data):
        if section.kind != SHT_NOTE:
            continue
        body = section_bytes(data, section)
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


def _one_wz_note(data: bytes, kind: int, section: str, what: str, required: bool) -> Note | None:
    found = [n for n in notes(data) if n.owner == STAMP_OWNER and n.kind == kind]
    if not found:
        if required:
            raise ElfError(f"the file carries no {what}")
        return None
    if len(found) > 1:
        raise ElfError(f"the file carries {len(found)} {what}s; an artifact has one")
    note = found[0]
    if note.section != section:
        raise ElfError(f"the {what} is in section {note.section}, not {section}")
    if not note.desc.endswith(b"\x00"):
        raise ElfError(f"the {what} is not NUL-terminated")
    return note


def _json_object(note: Note, what: str, keys: set[str]) -> dict:
    try:
        obj = json.loads(note.desc[:-1].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise ElfError(f"the {what} is not JSON: {err}") from err
    if not isinstance(obj, dict) or set(obj) != keys:
        raise ElfError(f"the {what} does not have exactly the keys {sorted(keys)}")
    if obj["schema"] != STAMP_SCHEMA:
        raise ElfError(f"the {what} is schema {obj['schema']!r}; this reader reads {STAMP_SCHEMA}")
    return obj


def read_abi_stamp(data: bytes) -> dict:
    """The one ABI stamp the file carries, parsed and checked against the stamp's own format.

    Exactly one note of owner `wz` and type 1 must exist, in the section the writer uses; none and
    two are both errors. The object must have exactly the four keys of schema 1.
    """
    note = _one_wz_note(data, STAMP_NOTE_TYPE, STAMP_SECTION, "ABI stamp", True)
    assert note is not None
    stamp = _json_object(note, "ABI stamp", STAMP_KEYS)
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


def read_facts(data: bytes) -> dict[str, list[str]] | None:
    """The named lists of the file's facts note, or None when the file carries none.

    A file with no facts note is not an error (a library has none); a file with a malformed one,
    or two, is.
    """
    note = _one_wz_note(data, FACTS_NOTE_TYPE, FACTS_SECTION, "facts note", False)
    if note is None:
        return None
    facts = _json_object(note, "facts note", FACTS_KEYS)
    lists = facts["lists"]
    if not isinstance(lists, dict) or not all(
        isinstance(v, list) and all(isinstance(w, str) for w in v) for v in lists.values()
    ):
        raise ElfError("the facts note's lists are not an object of lists of words")
    return lists


def header_facts(data: bytes) -> dict:
    """The class and the machine from the ELF header."""
    end = _byte_order(data)
    (machine,) = struct.unpack_from(end + "H", _span(data, 0x12, 2, "the ELF header"), 0)
    return {"class": 64 if data[4] == 2 else 32, "machine": MACHINES.get(machine, f"unknown-{machine}")}


def _cstring(table: bytes, offset: int, what: str) -> str:
    if offset >= len(table):
        raise ElfError(f"{what} points outside the string table")
    stop = table.find(b"\x00", offset)
    if stop < 0:
        raise ElfError(f"{what} is not terminated in the string table")
    return table[offset:stop].decode("utf-8", "replace")


def _linked_strings(data: bytes, secs: list[Section], section: Section) -> bytes:
    if section.link >= len(secs):
        raise ElfError(f"{section.name} links to a section that does not exist")
    return section_bytes(data, secs[section.link])


def dynamic_facts(data: bytes) -> dict:
    """linking, NEEDED, SONAME, RUNPATH and RPATH, and the interpreter.

    `linking` is `static` when the file has no dynamic section and `dynamic` when it has one; a
    static PIE has one and is reported `dynamic` with nothing needed, which says what a loader sees.
    """
    end = _byte_order(data)
    secs = sections(data)
    interp = next((s for s in secs if s.name == ".interp"), None)
    interpreter = None
    if interp is not None:
        interpreter = section_bytes(data, interp).rstrip(b"\x00").decode("utf-8", "replace")
    dyn = next((s for s in secs if s.kind == SHT_DYNAMIC), None)
    if dyn is None:
        return {"linking": "static", "needed": [], "soname": None, "runpath": None, "rpath": None,
                "interpreter": interpreter}
    strings = _linked_strings(data, secs, dyn)
    fmt = end + ("qQ" if data[4] == 2 else "iI")
    size = struct.calcsize(fmt)
    body = section_bytes(data, dyn)
    needed: list[str] = []
    out: dict = {"soname": None, "runpath": None, "rpath": None}
    for pos in range(0, len(body) - size + 1, size):
        tag, value = struct.unpack_from(fmt, body, pos)
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED:
            needed.append(_cstring(strings, value, "a NEEDED entry"))
        elif tag == DT_SONAME:
            out["soname"] = _cstring(strings, value, "the SONAME")
        elif tag == DT_RUNPATH:
            out["runpath"] = _cstring(strings, value, "the RUNPATH")
        elif tag == DT_RPATH:
            out["rpath"] = _cstring(strings, value, "the RPATH")
    return {"linking": "dynamic", "needed": needed, **out, "interpreter": interpreter}


def version_tags(data: bytes) -> list[str]:
    """The symbol-version tags the file asks the C library for (its `.gnu.version_r`), sorted."""
    end = _byte_order(data)
    secs = sections(data)
    need = next((s for s in secs if s.kind == SHT_GNU_VERNEED), None)
    if need is None:
        return []
    strings = _linked_strings(data, secs, need)
    body = section_bytes(data, need)
    tags: set[str] = set()
    pos = 0
    seen = 0
    while True:
        if pos + 16 > len(body):
            raise ElfError("a version-need entry is cut short")
        _version, count, _file, aux, nxt = struct.unpack_from(end + "HHIII", body, pos)
        apos = pos + aux
        for _ in range(count):
            if apos + 16 > len(body):
                raise ElfError("a version-need auxiliary entry is cut short")
            _hash, _flags, _other, name, anext = struct.unpack_from(end + "IHHII", body, apos)
            tags.add(_cstring(strings, name, "a version tag"))
            if anext == 0:
                break
            apos += anext
        seen += 1
        if nxt == 0 or seen > len(body):
            break
        pos += nxt
    return sorted(tags)


def imported_symbols(data: bytes) -> list[str]:
    """The symbols the file's code can call in another object (the C library, for an artifact of
    this tree), sorted: each is undefined in the dynamic symbol table AND bound by a dynamic
    relocation, the GOT or PLT slot a call goes through.

    The relocation is what makes it a call. The linker can leave an undefined symbol in the table
    after dropping the only code that used it (measured: a pico library listed `fork` and `execvp`
    with no relocation naming either), and no code can reach a shared object's function without a
    slot. Both tables survive `strip`, since the loader binds through them, and they hold only what
    the linker kept, so a call in code a feature left out is in neither."""
    end = _byte_order(data)
    secs = sections(data)
    table_index = next((i for i, s in enumerate(secs) if s.kind == SHT_DYNSYM), None)
    if table_index is None:
        return []
    table = secs[table_index]
    strings = _linked_strings(data, secs, table)
    body = section_bytes(data, table)
    wide = data[4] == 2
    if wide:
        size, layout = 24, end + "IBBHQQ"  # name, info, other, shndx, value, size
    else:
        size, layout = 16, end + "IIIBBH"  # name, value, size, info, other, shndx
    if len(body) % size:
        raise ElfError(f"the dynamic symbol table is {len(body)} bytes, not a whole number of {size}-byte entries")
    count = len(body) // size
    bound: set[int] = set()
    for section in secs:
        if section.kind not in (SHT_REL, SHT_RELA) or section.link != table_index:
            continue
        entry = (24 if section.kind == SHT_RELA else 16) if wide else (12 if section.kind == SHT_RELA else 8)
        rel = section_bytes(data, section)
        if len(rel) % entry:
            raise ElfError(f"relocation section {section.name} is not a whole number of {entry}-byte entries")
        for pos in range(0, len(rel), entry):
            (info,) = struct.unpack_from(end + ("Q" if wide else "I"), rel, pos + (8 if wide else 4))
            index = info >> 32 if wide else info >> 8
            if index >= count:
                raise ElfError(f"relocation section {section.name} names symbol {index} of {count}")
            bound.add(index)
    names: set[str] = set()
    for index in sorted(bound - {0}):  # symbol 0 is the null symbol
        fields = struct.unpack_from(layout, body, index * size)
        name, shndx = fields[0], (fields[3] if wide else fields[5])
        if shndx == SHN_UNDEF and name:
            names.add(_cstring(strings, name, "a dynamic symbol name"))
    return sorted(names)


def glibc_floor(tags: list[str]) -> str | None:
    """The highest `GLIBC_x.y[.z]` tag, compared as numbers, or None when there is none."""
    best: tuple[int, ...] | None = None
    best_tag = None
    for tag in tags:
        if not tag.startswith("GLIBC_"):
            continue
        try:
            numbers = tuple(int(part) for part in tag[len("GLIBC_"):].split("."))
        except ValueError:
            continue
        if best is None or numbers > best:
            best, best_tag = numbers, tag
    return best_tag


def android_api(data: bytes) -> int | None:
    """The API level of Android's identification note, or None when the file has none."""
    end = _byte_order(data)
    found = [n for n in notes(data)
             if n.section == ANDROID_NOTE_SECTION and n.owner == ANDROID_NOTE_OWNER
             and n.kind == ANDROID_NOTE_TYPE]
    if not found:
        return None
    if len(found) > 1 or len(found[0].desc) < 4:
        raise ElfError("the Android identification note is malformed")
    return struct.unpack_from(end + "I", found[0].desc, 0)[0]


def linkage_facts(data: bytes) -> dict:
    """The facts any ELF has, read the same way for a file wz built and for one it only carries (a
    library bundled from an SDK, which has no wz note)."""
    tags = version_tags(data)
    return {
        **header_facts(data),
        **dynamic_facts(data),
        "symbol_version_tags": tags,
        "glibc_floor": glibc_floor(tags),
        "android_api_note": android_api(data),
    }


def describe(data: bytes) -> dict:
    """Every fact of the module for one file wz built, as the manifest records them: the linkage
    facts and the wz notes, the stamp being required."""
    return {
        **linkage_facts(data),
        "abi_stamp": read_abi_stamp(data),
        "facts": read_facts(data),
    }


# ---------------------------------------------------------------------------
# A small ELF for tests: the sections a test asks for, and nothing else.
# ---------------------------------------------------------------------------


def _pad4(blob: bytes) -> bytes:
    return blob + b"\x00" * (-len(blob) % 4)


def build_elf(
    parts: list[tuple[str, int, bytes, str | None]],
    cls: int = 64,
    order: str = "<",
    machine: int = 183,
) -> bytes:
    """An ELF with no segments and the given sections: (name, type, content, linked section)."""
    names = b"\x00"
    name_off = {}
    for name, *_ in parts:
        name_off[name] = len(names)
        names += name.encode() + b"\x00"
    name_off[".shstrtab"] = len(names)
    names += b".shstrtab\x00"
    header_size = 64 if cls == 64 else 52
    body = b""
    placed = []
    for name, kind, content, link in parts:
        placed.append((name, kind, header_size + len(body), len(content), link))
        body += _pad4(content)
    names_off = header_size + len(body)
    body += _pad4(names)
    shoff = header_size + len(body)
    index = {name: i + 1 for i, (name, *_) in enumerate(parts)}
    shdr = order + ("IIQQQQIIQQ" if cls == 64 else "IIIIIIIIII")
    table = struct.pack(shdr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for name, kind, off, size, link in placed:
        table += struct.pack(shdr, name_off[name], kind, 2, 0, off, size, index[link] if link else 0, 0, 4, 0)
    table += struct.pack(shdr, name_off[".shstrtab"], SHT_STRTAB, 0, 0, names_off, len(names), 0, 0, 1, 0)
    count = len(parts) + 2
    ident = b"\x7fELF" + bytes([1 if cls == 32 else 2, 1 if order == "<" else 2, 1]) + b"\x00" * 9
    if cls == 64:
        head = ident + struct.pack(order + "HHIQQQIHHHHHH", 3, machine, 1, 0, 0, shoff, 0, 64, 0, 0, 64, count, count - 1)
    else:
        head = ident + struct.pack(order + "HHIIIIIHHHHHH", 3, machine, 1, 0, 0, shoff, 0, 52, 0, 0, 40, count, count - 1)
    assert len(head) == header_size, (len(head), header_size)
    return head + body + table


def note_blob(owner: str, kind: int, desc: bytes, order: str = "<") -> bytes:
    name = owner.encode() + b"\x00"
    return struct.pack(order + "III", len(name), len(desc), kind) + _pad4(name) + _pad4(desc)


def build_test_elf(
    notes_: list[tuple[str, str, int, bytes]] | None = None,
    needed: list[str] | None = None,
    soname: str | None = None,
    runpath: str | None = None,
    rpath: str | None = None,
    interp: str | None = None,
    verneed: list[tuple[str, list[str]]] | None = None,
    cls: int = 64,
    order: str = "<",
    machine: int = 183,
    dynamic: bool | None = None,
    symbols: list[tuple[str, bool, bool]] | None = None,
) -> bytes:
    """A test ELF: notes as (section, owner, type, desc), a dynamic section when any of its fields is
    given (or `dynamic=True`), an interpreter, version needs as (file, [tags]) and dynamic symbols
    as (name, defined, bound by a relocation)."""
    parts: list[tuple[str, int, bytes, str | None]] = []
    for section, owner, kind, desc in notes_ or []:
        parts.append((section, SHT_NOTE, note_blob(owner, kind, desc, order), None))
    if interp is not None:
        parts.append((".interp", SHT_PROGBITS, interp.encode() + b"\x00", None))
    wants_dynamic = dynamic if dynamic is not None else any(
        x for x in (needed, soname, runpath, rpath, verneed, symbols))
    if wants_dynamic:
        strings_ref = [b"\x00"]
        offsets: dict[str, int] = {}

        def intern(text: str) -> int:
            if text not in offsets:
                offsets[text] = len(strings_ref[0])
                strings_ref[0] += text.encode() + b"\x00"
            return offsets[text]

        fmt = order + ("qQ" if cls == 64 else "iI")
        entries = b""
        for lib in needed or []:
            entries += struct.pack(fmt, DT_NEEDED, intern(lib))
        if soname:
            entries += struct.pack(fmt, DT_SONAME, intern(soname))
        if rpath:
            entries += struct.pack(fmt, DT_RPATH, intern(rpath))
        if runpath:
            entries += struct.pack(fmt, DT_RUNPATH, intern(runpath))
        entries += struct.pack(fmt, DT_NULL, 0)
        vn = b""
        files = verneed or []
        for fi, (lib, tags) in enumerate(files):
            nxt = 16 + 16 * len(tags) if fi + 1 < len(files) else 0
            vn += struct.pack(order + "HHIII", 1, len(tags), intern(lib), 16, nxt)
            for ti, tag in enumerate(tags):
                anext = 16 if ti + 1 < len(tags) else 0
                vn += struct.pack(order + "IHHII", 0, 0, 2 + ti, intern(tag), anext)
        sym_layout = order + ("IBBHQQ" if cls == 64 else "IIIBBH")
        syms = struct.pack(sym_layout, *([0] * 6))
        relocs = b""
        for index, (name, defined, relocated) in enumerate(symbols or [], start=1):
            shndx = 1 if defined else SHN_UNDEF
            fields = (intern(name), 0x12, 0, shndx, 0, 0) if cls == 64 else (intern(name), 0, 0, 0x12, 0, shndx)
            syms += struct.pack(sym_layout, *fields)
            if relocated:  # a GLOB_DAT slot (type 6), as a call through the GOT has
                relocs += (struct.pack(order + "QQq", 0, index << 32 | 6, 0) if cls == 64
                           else struct.pack(order + "IIi", 0, index << 8 | 6, 0))
        parts.append((".dynstr", SHT_STRTAB, strings_ref[0], None))
        parts.append((".dynamic", SHT_DYNAMIC, entries, ".dynstr"))
        if files:
            parts.append((".gnu.version_r", SHT_GNU_VERNEED, vn, ".dynstr"))
        if symbols:
            parts.append((".dynsym", SHT_DYNSYM, syms, ".dynstr"))
            parts.append((".rela.dyn", SHT_RELA, relocs, ".dynsym"))
    return build_elf(parts, cls, order, machine)


def _selftest() -> int:
    def expect(label: str, condition: bool) -> None:
        if not condition:
            raise AssertionError(f"selftest: {label}")

    stamp = json.dumps({"schema": 1, "family": "f", "revision": 3, "layout": {"k": True}},
                       separators=(",", ":")).encode() + b"\x00"
    facts = json.dumps({"schema": 1, "lists": {"r": ["a", "b"]}}, separators=(",", ":")).encode() + b"\x00"
    for cls, order in [(64, "<"), (32, "<"), (64, ">"), (32, ">")]:
        android = struct.pack(order + "I", 36) + b"r30\x00".ljust(60, b"\x00")
        elf = build_test_elf(
            notes_=[(STAMP_SECTION, "wz", 1, stamp), (FACTS_SECTION, "wz", 2, facts),
                    (ANDROID_NOTE_SECTION, "Android", 1, android)],
            needed=["libc.so.6", "libm.so.6"], soname="libx.so", runpath="$ORIGIN", rpath="/r",
            interp="/lib/ld-linux-aarch64.so.1",
            verneed=[("libc.so.6", ["GLIBC_2.17", "GLIBC_2.34", "GLIBC_2.5"]), ("libm.so.6", ["GLIBC_2.27"])],
            cls=cls, order=order)
        label = f"ELF{cls} {order!r}"
        got = describe(elf)
        expect(f"{label}: the header facts", got["class"] == cls and got["machine"] == "aarch64")
        expect(f"{label}: needed in order", got["needed"] == ["libc.so.6", "libm.so.6"])
        expect(f"{label}: soname, runpath, rpath",
               (got["soname"], got["runpath"], got["rpath"]) == ("libx.so", "$ORIGIN", "/r"))
        expect(f"{label}: interpreter", got["interpreter"] == "/lib/ld-linux-aarch64.so.1")
        expect(f"{label}: dynamic linking", got["linking"] == "dynamic")
        expect(f"{label}: every version tag, sorted",
               got["symbol_version_tags"] == ["GLIBC_2.17", "GLIBC_2.27", "GLIBC_2.34", "GLIBC_2.5"])
        expect(f"{label}: the glibc floor is compared as numbers (2.34 over 2.5)", got["glibc_floor"] == "GLIBC_2.34")
        expect(f"{label}: the android API", got["android_api_note"] == 36)
        expect(f"{label}: the stamp and the facts",
               got["abi_stamp"]["revision"] == 3 and got["facts"] == {"r": ["a", "b"]})
    plain = build_test_elf(notes_=[(STAMP_SECTION, "wz", 1, stamp)], machine=62)
    got = describe(plain)
    expect("a file with no dynamic section is static and has nothing needed",
           (got["linking"], got["needed"], got["soname"], got["interpreter"]) == ("static", [], None, None))
    expect("a file with no version needs has no tags and no floor",
           (got["symbol_version_tags"], got["glibc_floor"], got["android_api_note"], got["facts"])
           == ([], None, None, None))
    expect("the machine is named", got["machine"] == "x86_64")
    expect("an unknown machine is reported by number, not guessed",
           header_facts(build_test_elf(machine=9999))["machine"] == "unknown-9999")
    expect("bionic tags have no glibc floor", glibc_floor(["LIBC", "LIBC_N"]) is None)
    expect("a tag that is not a number is skipped", glibc_floor(["GLIBC_x", "GLIBC_2.3"]) == "GLIBC_2.3")
    for what, broken in [
        ("two facts notes", build_test_elf(notes_=[(FACTS_SECTION, "wz", 2, facts)] * 2)),
        ("a facts note in the wrong section", build_test_elf(notes_=[("other", "wz", 2, facts)])),
        ("a facts note with no NUL", build_test_elf(notes_=[(FACTS_SECTION, "wz", 2, facts[:-1])])),
        ("a facts note with an extra key", build_test_elf(notes_=[(FACTS_SECTION, "wz", 2, json.dumps(
            {"schema": 1, "lists": {}, "x": 1}).encode() + b"\x00")])),
        ("a facts note of lists of numbers", build_test_elf(notes_=[(FACTS_SECTION, "wz", 2, json.dumps(
            {"schema": 1, "lists": {"r": [1]}}).encode() + b"\x00")])),
    ]:
        try:
            read_facts(broken)
        except ElfError:
            continue
        raise AssertionError(f"selftest: {what} was read")
    # A dynamic entry whose string offset is outside the table is a refusal, not a blank name.
    dyn_bad = build_elf([
        (".dynstr", SHT_STRTAB, b"\x00abc\x00", None),
        (".dynamic", SHT_DYNAMIC, struct.pack("<qQ", DT_NEEDED, 500) + struct.pack("<qQ", DT_NULL, 0), ".dynstr"),
    ])
    try:
        dynamic_facts(dyn_bad)
    except ElfError:
        pass
    else:
        raise AssertionError("selftest: a NEEDED offset outside the table was read")
    for cut in (10, 40, 70):
        try:
            describe(build_test_elf(notes_=[(STAMP_SECTION, "wz", 1, stamp)], needed=["a.so"])[:cut])
        except ElfError:
            continue
        raise AssertionError(f"selftest: a file cut at {cut} bytes was described")
    for cls, order in ((64, "<"), (32, "<"), (64, ">"), (32, ">")):
        with_syms = build_test_elf(needed=["libc.so.6"], cls=cls, order=order,
                                   symbols=[("socket", False, True), ("wz_export", True, True),
                                            ("fork", False, False), ("getifaddrs", False, True)])
        expect(f"the {cls}-bit {order} file imports its undefined, relocated symbols, sorted, "
               "and not an undefined one no slot binds",
               imported_symbols(with_syms) == ["getifaddrs", "socket"])
    expect("a file with no dynamic symbol table imports nothing",
           imported_symbols(build_test_elf(needed=["libc.so.6"])) == [])
    print("elf-facts: selftest OK")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        try:
            sys.exit(_selftest())
        except AssertionError as err:
            print(f"elf-facts: FAIL -- {err}", file=sys.stderr)
            sys.exit(1)
    print("usage: elf_facts.py --selftest", file=sys.stderr)
    sys.exit(2)
