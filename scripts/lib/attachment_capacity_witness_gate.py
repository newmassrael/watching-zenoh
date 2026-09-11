#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2546 (no register item) — the attachment's declared capacity is ADVISORY
under `alloc`, and only two of its three carriers ever said so.

The citation is `no register item` for the reason `debt_plane_census.py` gives
for its own: this closes the last clause of the `attachment-bytes` ATOM, which
is graded in the atomic store rather than the debt register, and the clause is
named in prose below.

## The two facts this gate holds together

`sources/codecs/ext_zbuf.scxml` declares `sce:max-size="32"` on the ext-zbuf
body's `value` field. That number is the INLINE (heap-free) capacity of every
ENC_ZBUF extension body, attachment included. Under `alloc` the owned
projection is a growable `Vec` and the 32 is advisory, which is what lets wz
match zenoh's unbounded attachment (`commons/zenoh-protocol/src/zenoh/put.rs`
@ `pub type Attachment = zextzbuf!(0x3, false);` carries no ceiling).

"Advisory" is a claim about behaviour, so it needs a witness per carrier, and
the carriers are not one: the attachment ext is declared at a DIFFERENT id per
body — `0x03` on a Put push, `0x02` on a Del push, `0x05` on a Query — and each
id is emitted by a different builder. A payload larger than the declared
capacity riding one of them says nothing about the others.

## What was actually measured, R2546

Damaging the encoder to truncate at the declared capacity
(`owned_bytes(&payload[..payload.len().min(32)])`) redded exactly TWO tests:

    request_build::tests::build_request_query_with_attachment_carries_over_32_under_alloc
    response_build::tests::response_reply_builder_attachment_carries_aligner_sized_payload

So the QUERY carrier and the reply's inner MsgPut (which uses the PUSH id) were
witnessed, and the two PUSH-BODY builder arms — a publisher's own `put()` and
`del()` — were not. A `del()` carrying a 200-byte attachment was green by not
being tried, on the one carrier whose id wz had already had to fix once
(R311y769, R2370).

## The second half: a hand-written 32 that nothing bound to the SSOT

`crates/wz-session-core/src/request_build.rs` @ `QUERY_EXT_ZBUF_MAX_LEN` spells
the codegen capacity again, in Rust, and the boundary witnesses compare their
payload against IT (or against a bare `32`). Nothing made the two agree. Raise
`sce:max-size` past a witness's payload length and every witness keeps passing
while witnessing nothing — the assertion `big.len() > 32` stays true and stops
meaning "over capacity". That is the tripwire-vs-copy split this tree has paid
for before (R2540, open-debt item 690): a constant that spells a pinned value
is only a tripwire while something compares it to the pin.

## What it derives rather than declares

  * the capacity comes from the SCXML attribute, parsed off the `value` field;
  * the carrier set comes from the `pub const ATTACHMENT_EXT_ID_*` declarations
    in the attachment SSOT module — not a list here, so a fourth carrier is
    covered the moment it is declared;
  * a witness is attributed to a carrier by naming that carrier's CONST or by
    asserting its `ENC_ZBUF | id` header literal, so a test may keep using the
    literal form R2470 required (comparing an emitted header against the
    producer's own constant is a tautology, and that is how the Del id went
    ungraded for four months).

Every anchor is a HARD FAIL when absent, and an empty carrier set is a HARD
FAIL: a gate whose population is zero reports green for the wrong reason.

Usage:
    attachment_capacity_witness_gate.py            # grade the worktree
    attachment_capacity_witness_gate.py --selftest # drive both arms
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

SCXML = "sources/codecs/ext_zbuf.scxml"
ATTACHMENT_SSOT = "crates/wz-session-core/src/attachment.rs"
QUERY_CAP_CONST_FILE = "crates/wz-session-core/src/request_build.rs"
QUERY_CAP_CONST = "QUERY_EXT_ZBUF_MAX_LEN"

# The ENC_ZBUF encoding marker the attachment ext header carries (`0b10 << 5`).
ENC_ZBUF = 0x40


class GateError(Exception):
    """An anchor this gate reads is missing or unreadable — never a pass."""


# ── source readers ───────────────────────────────────────────────────

def declared_capacity(scxml_text: str) -> int:
    """The `sce:max-size` on the ext-zbuf body's `value` field.

    Anchored on the field id so a second `max-size` appearing in the file
    (a sibling field, or the prose header that explains the number) cannot be
    picked up instead.
    """
    field = re.search(
        r'<sce:field\b[^>]*\bid="value"[^>]*>', scxml_text, re.S
    )
    if field is None:
        raise GateError(f"{SCXML}: no `<sce:field id=\"value\" …>` to read")
    cap = re.search(r'sce:max-size="(\d+)"', field.group(0))
    if cap is None:
        raise GateError(
            f"{SCXML}: the `value` field declares no `sce:max-size` — the "
            "capacity this gate grades has no source"
        )
    return int(cap.group(1))


def carrier_ids(attachment_text: str) -> dict[str, int]:
    """`{const name: ext id}` for every attachment carrier the SSOT declares."""
    found = {
        m.group(1): int(m.group(2), 0)
        for m in re.finditer(
            r"pub const (ATTACHMENT_EXT_ID_[A-Z_]+)\s*:\s*u8\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;",
            attachment_text,
        )
    }
    if not found:
        raise GateError(
            f"{ATTACHMENT_SSOT}: no `pub const ATTACHMENT_EXT_ID_*` — the "
            "carrier population is empty, which is not a pass"
        )
    return found


def rust_const_usize(text: str, name: str, where: str) -> int:
    m = re.search(rf"pub const {re.escape(name)}\s*:\s*usize\s*=\s*(\d+)\s*;", text)
    if m is None:
        raise GateError(f"{where}: no `pub const {name}: usize = …;` to read")
    return int(m.group(1))


# ── a minimal Rust scanner: `#[test]` fn bodies ──────────────────────

def _strip_uninteresting(src: str) -> str:
    """Blank out comments and string / char literals, preserving offsets.

    Brace matching below must not be thrown by a `{` inside a doc comment or a
    raw string, and both occur in this tree's tests.
    """
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                elif src.startswith("*/", i):
                    depth -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                else:
                    if src[i] != "\n":
                        out[i] = " "
                    i += 1
        elif c == "r" and i + 1 < n and src[i + 1] in '#"':
            j = i + 1
            hashes = 0
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                close = '"' + "#" * hashes
                end = src.find(close, j + 1)
                end = n if end < 0 else end + len(close)
                for k in range(i, end):
                    if src[k] != "\n":
                        out[k] = " "
                i = end
            else:
                i += 1
        elif c == '"':
            out[i] = " "
            i += 1
            while i < n:
                if src[i] == "\\":
                    out[i] = " "
                    if i + 1 < n and src[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if src[i] == '"':
                    out[i] = " "
                    i += 1
                    break
                if src[i] != "\n":
                    out[i] = " "
                i += 1
        else:
            i += 1
    return "".join(out)


def test_bodies(src: str) -> list[tuple[str, str]]:
    """`[(fn name, body)]` for every `#[test]` function in one Rust file."""
    blanked = _strip_uninteresting(src)
    bodies = []
    for m in re.finditer(r"#\[test\]", blanked):
        fn = re.search(r"\bfn\s+([A-Za-z0-9_]+)\s*\(", blanked[m.end():])
        if fn is None:
            continue
        open_brace = blanked.find("{", m.end() + fn.end())
        if open_brace < 0:
            continue
        depth, i, n = 0, open_brace, len(blanked)
        while i < n:
            if blanked[i] == "{":
                depth += 1
            elif blanked[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        bodies.append((fn.group(1), src[open_brace:i + 1]))
    return bodies


def rust_sources(root: Path) -> list[Path]:
    files = []
    crates = root / "crates"
    if not crates.is_dir():
        raise GateError("crates/: not a directory — nothing to scan")
    for path in crates.rglob("*.rs"):
        if "/target/" in str(path):
            continue
        files.append(path)
    if not files:
        raise GateError("crates/: no Rust sources found — an empty scan is not a pass")
    return files


# ── the grading ──────────────────────────────────────────────────────

def asserts_over_capacity(body: str, cap: int) -> bool:
    """Does this test assert its payload EXCEEDS the declared capacity?

    Accepts the two forms the existing witnesses use: a comparison against the
    Rust mirror of the capacity, or against its literal value. The runtime
    assertion is what proves the payload is actually over capacity; this gate's
    job is that the claim is made at all, and made against the right number.
    """
    if re.search(rf"\.len\(\)\s*>\s*{QUERY_CAP_CONST}\b", body):
        return True
    return bool(re.search(rf"\.len\(\)\s*>\s*{cap}\b", body))


def witnesses(root: Path, carriers: dict[str, int], cap: int) -> dict[str, list[str]]:
    """`{carrier const: [witness fn names]}` over the whole workspace."""
    found: dict[str, list[str]] = {name: [] for name in carriers}
    for path in rust_sources(root):
        src = path.read_text(encoding="utf-8", errors="replace")
        # The only sound prefilter is the one that cannot hide a witness: a
        # file with no `#[test]` has none. Filtering on "attachment" instead
        # would skip a test that attributes itself by the header LITERAL
        # alone — the very form R2470 required — and a hidden witness reads as
        # a missing one, which is a gate failing for the wrong reason.
        if "#[test]" not in src:
            continue
        for fn, body in test_bodies(src):
            if not asserts_over_capacity(body, cap):
                continue
            for name, ext_id in carriers.items():
                header = ENC_ZBUF | ext_id
                attributed = name in body or re.search(
                    rf"0x{header:02X}\b", body, re.IGNORECASE
                )
                if attributed:
                    found[name].append(f"{path.relative_to(root)}::{fn}")
    return found


def grade(root: Path) -> list[str]:
    """`[]` when every carrier is witnessed and the mirror is bound."""
    cap = declared_capacity((root / SCXML).read_text(encoding="utf-8"))
    carriers = carrier_ids((root / ATTACHMENT_SSOT).read_text(encoding="utf-8"))
    mirror = rust_const_usize(
        (root / QUERY_CAP_CONST_FILE).read_text(encoding="utf-8"),
        QUERY_CAP_CONST,
        QUERY_CAP_CONST_FILE,
    )

    failures = []
    if mirror != cap:
        failures.append(
            f"{QUERY_CAP_CONST_FILE}: {QUERY_CAP_CONST} = {mirror} but "
            f"{SCXML} declares sce:max-size={cap}. The Rust constant is a "
            "TRIPWIRE for the codegen capacity, not a copy of it — move both "
            "in one commit, and re-check that every boundary witness still "
            "carries a payload longer than the new number."
        )

    seen = witnesses(root, carriers, cap)
    print(
        f"attachment capacity witness: cap={cap} from {SCXML}; "
        f"{len(carriers)} carrier(s) declared"
    )
    for name, ext_id in sorted(carriers.items(), key=lambda kv: kv[1]):
        hits = seen[name]
        mark = "OK " if hits else "GAP"
        print(f"  {mark} {name} (0x{ext_id:02X}) -> {len(hits)} witness(es)")
        for h in hits:
            print(f"        {h}")
        if not hits:
            failures.append(
                f"{name} (ext id 0x{ext_id:02X}) has NO over-capacity witness: "
                f"no `#[test]` names it (or asserts its 0x{ENC_ZBUF | ext_id:02X} "
                f"header) while asserting a payload longer than {cap}. Under "
                "`alloc` this carrier's attachment is supposed to be unbounded "
                "like zenoh's; nothing proves it."
            )
    return failures


# ── selftest ─────────────────────────────────────────────────────────

def _selftest() -> int:
    import tempfile

    def build(tmp: Path, *, cap: int, mirror: int, witness_ids: list[int]) -> Path:
        root = tmp / "tree"
        (root / "sources/codecs").mkdir(parents=True, exist_ok=True)
        (root / "crates/wz-session-core/src").mkdir(parents=True, exist_ok=True)
        (root / SCXML).write_text(
            '<scxml><datamodel><sce:field id="value_len"/>'
            f'<sce:field id="value" sce:max-size="{cap}"/>'
            "</datamodel></scxml>\n"
        )
        (root / ATTACHMENT_SSOT).write_text(
            "pub const ATTACHMENT_EXT_ID_PUSH: u8 = 0x03;\n"
            "pub const ATTACHMENT_EXT_ID_DEL: u8 = 0x02;\n"
        )
        tests = "\n".join(
            "#[test]\n"
            f"fn witness_{i:02x}() {{\n"
            f"    // a body brace in a comment {{ and a string \"}}\"\n"
            f"    assert!(big.len() > {mirror}, \"over capacity\");\n"
            f"    assert_eq!(h & 0x4F, 0x{ENC_ZBUF | i:02X});\n"
            "}\n"
            for i in witness_ids
        )
        (root / QUERY_CAP_CONST_FILE).write_text(
            f"pub const {QUERY_CAP_CONST}: usize = {mirror};\n" + tests
        )
        return root

    ok = True
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # Arm 1 — every carrier witnessed and the mirror bound: PASS.
        root = build(tmp / "a", cap=32, mirror=32, witness_ids=[0x03, 0x02])
        fails = grade(root)
        if fails:
            print(f"SELFTEST FAIL: the green arm reported {fails}")
            ok = False

        # Arm 2 — a carrier with no over-capacity witness: FAIL, and the
        # message must name that carrier rather than the other one.
        root = build(tmp / "b", cap=32, mirror=32, witness_ids=[0x03])
        fails = grade(root)
        if not any("ATTACHMENT_EXT_ID_DEL" in f for f in fails):
            print(f"SELFTEST FAIL: the uncovered carrier was not named: {fails}")
            ok = False

        # Arm 3 — the codegen capacity moved and the Rust mirror did not.
        root = build(tmp / "c", cap=64, mirror=32, witness_ids=[0x03, 0x02])
        fails = grade(root)
        if not any(QUERY_CAP_CONST in f for f in fails):
            print(f"SELFTEST FAIL: the unbound mirror was not caught: {fails}")
            ok = False

        # Arm 4 — an empty carrier population is a hard failure, never a pass.
        root = build(tmp / "d", cap=32, mirror=32, witness_ids=[0x03, 0x02])
        (root / ATTACHMENT_SSOT).write_text("// no carrier declared\n")
        try:
            grade(root)
            print("SELFTEST FAIL: an empty carrier set reported a verdict")
            ok = False
        except GateError:
            pass

    print("attachment capacity witness gate selftest: " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selftest":
        return _selftest()
    if len(argv) > 1:
        print(f"unknown argument: {argv[1]}", file=sys.stderr)
        return 2
    try:
        failures = grade(REPO)
    except GateError as exc:
        print(f"attachment capacity witness gate: {exc}", file=sys.stderr)
        return 1
    if failures:
        print("", file=sys.stderr)
        for f in failures:
            print(f"attachment capacity witness gate: {f}", file=sys.stderr)
        return 1
    print("attachment capacity witness gate OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
