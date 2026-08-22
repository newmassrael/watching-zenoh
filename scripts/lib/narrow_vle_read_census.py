#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y879 (no register item) — the NARROW VLE READ census.

Closes a defect found in its own round rather than a listed store item. The
open-debt numbers it touches live in the unregistered half of the register:
335 was the `weight` MISMATCH it carried (CLOSED R311y880), and 338 is the axis
it does NOT reach — nothing re-checks an ADJUDICATED verdict against upstream
after it is written, so a row can be right the day it lands and wrong after a
version bump without anything saying so.

R311y880 also refuted this file's own stated reason for carrying 335. The row
said closing it "needs an SCE capability or a different codegen model, not an
scxml retype", because SCE derives the read width from the storage type and
there is no wide-read/narrow-store form to declare. Both halves of that are
true and the conclusion still did not follow: the scxml declares the WIRE
width, and the value width belongs at the consumer boundary, so retyping the
field `uint64` and truncating once by name
(`wire_const::linkstate_weight_from_wire`) is exactly upstream's own model —
`uint_impl!(u16)` reads a full ZInt and casts. An adjudication's REASON can be
wrong in a direction that shuts a door (open-debt item 47), and this is the
instance that was written down inside the gate meant to prevent it.

## The class this exists for

A zint field whose value type is narrower than `u64` can be read two ways, and
upstream picks between them PER FIELD:

    Zenoh080Bounded<uN>   REFUSES a value that does not fit  (zenoh-codec/src/
                          core/zint.rs, `zint_impl_codec!`: `if (x & !MAX) != 0
                          { return Err(DidntRead) }`)
    Zenoh080 (plain)      TRUNCATES it                       (same file,
                          `uint_impl!`: `let x: u64 = self.read(reader)?;
                          Ok(x as $uint)`)

wz has exactly one reader of each shape (`SpanCursor::vle_u16` refuses,
`SpanCursor::vle_u16_truncated` truncates; `SceCursor::read_vle_uN` refuses),
and picking the wrong one is not a rendering nicety:

  * refuse where upstream truncates -> wz answers `Err` on a message the whole
    network reads to the end. In `parse_inbound_consuming` an `Err` consumes
    nothing, so the batch walk STOPS and every message behind it is lost.
  * truncate-less where upstream truncates -> wz reports a value no peer
    computes, and when the field SELECTS behaviour (the OAM id selects the
    linkstate body walk) wz acts differently from every conforming peer.

## Why a gate rather than care

The class has leaked three times, each found by hand and none by a test:

    R311y597  `weight` read narrow; upstream reads it plain    (fixed R311y880)
    R311y878  transport OAM `id` read narrow; upstream plain   (fixed R311y879)
    R311y879  network OAM `id` read wide, never truncated      (fixed R311y879)

Nothing compared wz's reader choice against upstream's codec choice, so the
fourth instance would have been found by hand too. This census is the
comparison: every narrow VLE read in wz-owned Rust must appear in ADJUDICATED
below with the upstream codec that decides it.

## What it pins, and what it does not

It pins the SET, not a count -- a count moves for two different reasons and
says which neither. A site that is absent from the table is a narrow read
nobody adjudicated; a table row with no site is an adjudication that has
outlived its code (the shape debt item 47 names). Both are FAIL.

It does NOT decide whether an entry's verdict is TRUE. `MISMATCH` rows are
carried deliberately, the same way `KNOWN_DIVERGENCES` carries pico's, so this
gate is green while the disagreement stays named. Whether wz should agree is a
round's judgement, not a scan's.

`vle_u16_truncated` is deliberately NOT censused: it reads `read_vle_u64` and
narrows afterwards, which is upstream's plain shape, so it is not a narrow
read. That is also why adding a truncating site never needs a table edit --
the gate is asked about the reader that can REFUSE.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# The trees whose Rust wz owns the reader choice in. `vendor/` is excluded
# because SCE's runtime is where `read_vle_uN` is DEFINED -- a definition is
# not a field, and wz does not choose there.
TREES = ("crates", "out")

# R2039 (open-debt item 343) — the widths are DERIVED, not spelled.
#
# `read_vle_u16(` / `.vle_u32(` / ... — every reader that can answer
# `VleWidthOverflow`. The list used to be written by hand as `8|16|32`, which
# is item 327's shape arriving in a second census: a reader at a width nobody
# thought of is invisible, and this gate reports OK over it. It had already
# rotted in the way a hand-written list does — `vle_u8` names no reader in this
# tree and never has, so one third of the alternation could not match anything.
#
# `u64` is excluded by the rule rather than by an exemption: nothing is
# narrower than the wire's own maximum, so a read into it cannot overflow.
WIDTH_DECL = re.compile(r"\bfn\s+(?:read_)?vle_u(\d+)\s*\(")
"""A cursor reader's DECLARATION, which is where a width enters this tree.

Anchored on `(` immediately after the digits on purpose: `vle_u16_truncated` is
a reader that TRUNCATES, and a truncating read has no upstream question to
adjudicate. Sweeping it in would put a row in this census that nothing can
answer.
"""


def narrow_widths(src: str) -> list[str]:
    """Every width `src` declares a narrow reader for, widest last."""
    found = sorted({w for w in WIDTH_DECL.findall(src) if int(w) < 64}, key=int)
    return [str(w) for w in found]


def call_pattern(widths: list[str]) -> re.Pattern[str]:
    """The read pattern for `widths`, or a hard failure.

    Raising rather than returning something harmless: an empty alternation
    would match nothing and this census would report a clean sweep over a tree
    it never looked at. That is the failure item 343 is about, and it must not
    be reachable through the repair for it.
    """
    if not widths:
        raise SystemExit(
            "narrow-vle: no narrow VLE reader is declared anywhere in the "
            "censused trees -- the derivation is dead and this census would "
            "report OK without having looked"
        )
    alt = "|".join(widths)
    return re.compile(
        rf"\b(?:self\.cur\.|cursor\.|c\.)?(read_vle_u(?:{alt})|vle_u(?:{alt}))\("
    )
ARG = re.compile(r"\(\s*\"([^\"]+)\"")
FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+|async\s+|unsafe\s+)*fn\s+([A-Za-z0-9_]+)")

# site key -> (verdict, why). The key is `<path>::<enclosing fn>::<field>`:
# a path and a NAME, never a line number, because a line number goes stale on
# an edit that changes nothing this gate is about.
#
# verdict is what UPSTREAM does, not what wz does:
#   REFUSE    upstream reads it through `Zenoh080Bounded<uN>` -- a narrow read
#             is the faithful one.
#   MISMATCH  upstream reads it plain (truncating) and wz still reads it
#             narrow. Carried, named, and owed to a register item.
ADJUDICATED: dict[str, tuple[str, str]] = {
    "crates/wz-session-core/src/dissect.rs::vle_u16::": (
        "REFUSE",
        "the PRIMITIVE, not a field: `SpanCursor::vle_u16` is the refusing "
        "reader itself. It has NO call site as of R311y880 -- `weight` was its "
        "last one and upstream truncates there -- and it is kept because "
        "`Zenoh080Bounded<u16>` is a real upstream shape whose u32 sibling "
        "decides `Encoding.id`. A new call site reds this gate until someone "
        "names the upstream codec for that field, which is the point.",
    ),
    "crates/wz-session-core/src/dissect.rs::vle_u32::": (
        "REFUSE",
        "the PRIMITIVE, as above -- `SpanCursor::vle_u32`.",
    ),
    "crates/wz-session-core/src/dissect.rs::walk_encoding::packed_id": (
        "REFUSE",
        "`Encoding.id` is written AND read through `Zenoh080Bounded::<u32>` "
        "(zenoh-codec/src/core/encoding.rs:47 and :64-65), so upstream itself "
        "answers `DidntRead` on a value past u32. The narrow read is right "
        "here, and this row is the CONTROL that keeps the gate from reading "
        "as `every narrow read is a bug`.",
    ),
    "out/wz-codecs/encoding.rs::decode::": (
        "REFUSE",
        "the generated sibling of `walk_encoding` above, and correct for the "
        "same reason: upstream's `Encoding` codec is `Zenoh080Bounded::<u32>` "
        "on both sides.",
    ),
}


KEPT_WITHOUT_CALLER: dict[str, str] = {
    "crates/wz-session-core/src/dissect.rs::vle_u16::": (
        "`Zenoh080Bounded<u16>` is a real upstream shape -- its `u32` sibling "
        "is what decides `Encoding.id` -- so the refusing reader stays for the "
        "field that selects it next. `weight` was its last caller and R311y880 "
        "moved that field to `vle_u16_truncated` because upstream truncates "
        "there, which emptied the call sites without making the reader wrong."
    ),
}
"""R2040 (open-debt item 344) — readers KEPT ON PURPOSE with nothing calling
them.

# What this stops, and why the census alone did not

Deleting one of these already reds the census: the `ADJUDICATED` row becomes an
adjudication outliving its code. Measured this round rather than assumed, by
deleting `vle_u16` and running it.

⚠ AND THE MESSAGE RATIFIED THE DELETION. It said "delete the row in the commit
that removed the read", which is right for a FIELD whose read genuinely went
away and wrong for a primitive somebody kept deliberately: it tells the person
how to FINISH the removal rather than what they are about to lose. Item 344 is
about exactly that reader -- "a primitive with no subject is what a later round
deletes without reading why".

# Both directions, so the claim cannot rot

A key here must be a reader with NO call site outside its own body. The day a
field selects it, the claim stops being true and this gate says so -- the entry
is then deleted because it was ANSWERED, not because it was in the way.
"""

CALLER = re.compile(r"\b(?:self\.cur\.|cursor\.|c\.)?((?:read_)?vle_u\d+)\(")
"""A call, with the reader's WHOLE name captured.

⚠ The `read_` prefix is part of the identity, not decoration. `vle_u16` is the
`SpanCursor` method this census adjudicates; `read_vle_u16` is the inner
cursor's primitive that the method's own body calls. Folding the prefix into an
optional group made the body's line read as a call to the method it defines --
found by mutating this file rather than by reading it, because the one place
that line appears today is inside that method, where the enclosing-function
guard hid it.
"""


def callers_outside(name: str, sources: list[tuple[str, str]]) -> list[str]:
    """`<path>:<line>` for every call to `name` that is not inside its own body.

    The reader's own definition calls the cursor primitive underneath it, so a
    naive count is never zero; the enclosing function is what separates a
    definition from a use.
    """
    out: list[str] = []
    for rel, src in sources:
        enclosing = ""
        for lineno, line in enumerate(src.splitlines(), start=1):
            m = FN.match(line)
            if m:
                enclosing = m.group(1)
            stripped = line.lstrip()
            if stripped.startswith("//") or enclosing == name:
                continue
            for hit in CALLER.finditer(line):
                if hit.group(1) == name:
                    out.append(f"{rel}:{lineno}")
    return out


def tracked_rust() -> list[Path]:
    """Every tracked `.rs` under the censused trees, per git.

    git rather than a glob so a build artifact or an untracked scratch file
    can never join the population -- the same reason the exclusion-integrity
    axis reads the VCS instead of the filesystem.
    """
    cmd = ["git", "-C", str(ROOT), "ls-files", "--", *(f"{t}/**/*.rs" for t in TREES)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"`git ls-files` failed (rc={proc.returncode}): "
            f"{proc.stderr.strip() or '<no stderr>'}"
        )
    return [ROOT / line for line in proc.stdout.splitlines() if line]


def census_text(rel: str, src: str, widths: list[str]) -> dict[str, str]:
    """site key -> `<path>:<line>`, over ONE source's text.

    Split out of [`census`] at R2039 so `--selftest` can drive the detector
    against a fixture. A gate whose recogniser can only be exercised by the
    tree it guards has no way to show it still recognises anything once that
    tree stops producing findings — which is open-debt item 343 exactly.
    """
    call_re = call_pattern(widths)
    found: dict[str, str] = {}
    enclosing = ""
    for lineno, line in enumerate(src.splitlines(), start=1):
        m = FN.match(line)
        if m:
            enclosing = m.group(1)
        # A doc comment naming the reader is prose about it, not a read.
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        call = call_re.search(line)
        if not call:
            continue
        arg = ARG.search(line, call.end() - 1)
        field = arg.group(1) if arg else ""
        found.setdefault(f"{rel}::{enclosing}::{field}", f"{rel}:{lineno}")
    return found


def census(paths: list[Path]) -> dict[str, str]:
    """site key -> `<path>:<line>`, for every narrow VLE read found."""
    sources = [(p.relative_to(ROOT).as_posix(), p.read_text()) for p in paths]
    # THE WIDTHS COME FROM THE SAME TREES THE READS DO, so a reader added in
    # one of them is visible in all of them on the same commit.
    widths: set[str] = set()
    for _, src in sources:
        widths.update(narrow_widths(src))
    found: dict[str, str] = {}
    for rel, src in sources:
        found.update(census_text(rel, src, sorted(widths, key=int)))
    return found


def selftest() -> int:
    """R2039 (debt-narrow-vle-selftest) — prove the DETECTOR still detects.

    # Why a census with nothing to report needs this

    Open-debt item 343: R311y880 paid off the last `MISMATCH`, so this gate now
    reports `0 carried as MISMATCH` — and a census that has stopped looking
    reports the same thing. The live population cannot tell the two apart,
    because the whole point of the repair was to empty it.

    A total blackout does fail already: with `found` empty, every `ADJUDICATED`
    row becomes an "adjudication that outlives its code" failure. What has no
    witness is PARTIAL blindness — a narrow read in a shape the pattern cannot
    see — and that is the one a new reader actually produces.

    So the detector is exercised against fixtures rather than against the tree,
    the way `verdict_leg_mutation.py --selftest` is for the same reason one gate
    over. Each case names what would be true if it were removed.
    """
    # The readers this tree declares, as `dissect.rs` declares them. Supplied
    # to every case because the real census pools widths across the censused
    # TREES rather than reading them out of the file it is scanning -- a
    # fixture that carried only its own call would derive an empty width set
    # and prove nothing.
    DECLS = (
        "    pub fn vle_u64(&mut self, name: &'static str) {}\n"
        "    pub fn vle_u16(&mut self, name: &'static str) {}\n"
        "    pub fn vle_u16_truncated(&mut self, name: &'static str) {}\n"
        "    pub fn vle_u32(&mut self, name: &'static str) {}\n"
    )
    cases: list[tuple[str, str, set[str]]] = [
        (
            "an ordinary narrow read is SEEN",
            'fn walk_encoding(c: &mut C) {\n    c.vle_u32("packed_id")?;\n}\n',
            {"fx.rs::walk_encoding::packed_id"},
        ),
        (
            "the `read_` spelling is seen too",
            'fn walk_x(c: &mut C) {\n    self.cur.read_vle_u16("id")?;\n}\n',
            {"fx.rs::walk_x::id"},
        ),
        (
            "a TRUNCATING reader is NOT a narrow read -- it cannot answer "
            "`VleWidthOverflow`, so claiming it would put a row in this census "
            "that has no upstream question to adjudicate",
            'fn walk_y(c: &mut C) {\n    c.vle_u16_truncated("weight")?;\n}\n',
            set(),
        ),
        (
            "prose about a reader is not a read",
            'fn walk_z(c: &mut C) {\n    // c.vle_u32("nope")\n}\n',
            set(),
        ),
        (
            "A WIDTH THIS TREE GAINS LATER IS SEEN. The pattern used to spell "
            "its widths by hand, so a reader at any other width was invisible "
            "and this gate stayed green over it -- item 327's shape, one census "
            "across",
            'fn vle_u24(&mut self, name: &str) {}\n'
            'fn walk_w(c: &mut C) {\n    c.vle_u24("hop")?;\n}\n',
            # BOTH keys, and the second one is not an accident: a reader's own
            # DECLARATION is a row in this census by design -- `ADJUDICATED`
            # carries `vle_u16` and `vle_u32` as "the PRIMITIVE, not a field"
            # precisely so a reader cannot enter the tree without someone
            # naming what upstream does at that width.
            {"fx.rs::vle_u24::", "fx.rs::walk_w::hop"},
        ),
    ]
    failed = False
    for name, src, want in cases:
        # ⚠ The widths are pooled over DECLS + the case, exactly as `census`
        # pools them over the trees; the keys come from the case alone, so a
        # declaration cannot masquerade as a read.
        widths = narrow_widths(DECLS + src)
        got = set(census_text("fx.rs", src, widths))
        if got != want:
            failed = True
            print(f"  narrow-vle SELFTEST FAIL: {name}\n    want {sorted(want)}\n    got  {sorted(got)}")
    if failed:
        return 1
    print(f"  narrow-vle selftest: {len(cases)} detector case(s) hold")
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    try:
        paths = tracked_rust()
    except RuntimeError as e:
        print(f"  narrow-vle FAIL: {e}", file=sys.stderr)
        return 1
    if not paths:
        # A census that measured nothing must never read as a census that
        # found nothing.
        print("  narrow-vle FAIL: no tracked Rust under " + ", ".join(TREES), file=sys.stderr)
        return 1

    found = census(paths)
    failed = False

    for key in sorted(found.keys() - ADJUDICATED.keys()):
        failed = True
        print(
            f"  narrow-vle FAIL: {found[key]} reads a zint into a narrow type "
            f"and nothing says whether upstream refuses or truncates there.\n"
            f"    Read the field's upstream codec: `Zenoh080Bounded<uN>` means "
            f"the narrow read is right, plain `Zenoh080` means it truncates and "
            f"a narrow read stops a batch walk on a message the network "
            f"delivers. Then add `{key}` to ADJUDICATED in {Path(__file__).name}."
        )

    for key in sorted(ADJUDICATED.keys() - found.keys()):
        failed = True
        # Round 2040 (item 344) — a reader KEPT ON PURPOSE gets a different
        # sentence. The one below tells a person how to finish removing a read
        # that genuinely went away; said over a deliberately-kept primitive it
        # would ratify the very deletion this entry exists to question.
        if key in KEPT_WITHOUT_CALLER:
            print(
                f"  narrow-vle FAIL: `{key}` is gone, and it was KEPT ON "
                f"PURPOSE with nothing calling it:\n    {KEPT_WITHOUT_CALLER[key]}\n"
                f"    If that reasoning no longer holds, say so and remove BOTH "
                f"this row and its KEPT_WITHOUT_CALLER entry. If it was removed "
                f"for having no caller, that is the thing the entry is about."
            )
            continue
        print(
            f"  narrow-vle FAIL: ADJUDICATED names `{key}`, which no longer "
            f"exists. An adjudication that outlives its code is the shape "
            f"open-debt item 47 is about — delete the row in the commit that "
            f"removed the read."
        )

    # Round 2040 (item 344) — AND THE CLAIM MUST STILL BE TRUE. A reader that
    # has gained a caller is no longer being kept for a field that has not
    # arrived; the field arrived. Deleting the entry then is an ANSWER rather
    # than a tidy-up, and this is what makes the difference legible.
    sources = [(p.relative_to(ROOT).as_posix(), p.read_text()) for p in paths]
    for key, why in sorted(KEPT_WITHOUT_CALLER.items()):
        if key not in ADJUDICATED:
            failed = True
            print(
                f"  narrow-vle FAIL: `{key}` is kept without a caller and is "
                f"not adjudicated -- a reader nothing calls still has to say "
                f"what upstream does at its width"
            )
        reader = key.rsplit("::", 2)[1]
        callers = callers_outside(reader, sources)
        if callers:
            failed = True
            print(
                f"  narrow-vle FAIL: `{reader}` is declared as kept WITHOUT a "
                f"caller, and it now has {len(callers)}: {', '.join(callers[:3])}. "
                f"The reason recorded for keeping it was: {why}\n"
                f"    Delete the KEPT_WITHOUT_CALLER entry -- the field it was "
                f"waiting for has arrived, which is the entry being answered "
                f"rather than the entry being wrong."
            )

    if failed:
        return 1

    mismatches = sorted(k for k, (v, _) in ADJUDICATED.items() if v == "MISMATCH")
    print(
        f"  narrow-vle: {len(found)} narrow zint read(s), every one adjudicated "
        f"against its upstream codec ({len(mismatches)} carried as MISMATCH)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
