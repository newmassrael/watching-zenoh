#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2288 (no register item) -- THE FOUR SN-RESOLUTION WORDS ARE UPSTREAM'S, AND
EVERY SITE THAT SPELLS ONE IS HELD TO THE SAME MAPPING.

## The citation

This answers the numeric open-debt register's item 611, which lives in the
operator's notes rather than in the store, so `gate_provenance_lint`'s item
grammar cannot resolve it. `zenoh_c_archive_arm.py` set the precedent for
declaring the escape hatch on the first line and naming the item in the body.

## The defect

`dissect.rs::sn_res_word` turns a 2-bit code into one of four words, and item
611 measured that only TWO of them were pinned to anything: the zenohd interop
lane feeds `"16bit"` and `"32bit"` to a genuine router, so upstream renaming
either would red that lane. `"8bit"` and `"64bit"` reached no oracle at all, and
what tied ANY of them to `sn_res_word` was a prose line in
`dissect_label_census.py`'s `DECIDED_BY_FUNCTION` -- the shape this tree states
as "prose written down is evidence nobody measures".

The crate's own unit test does not close it. That test holds the four words
against literals the same author wrote, which is R2185's self-counted table;
what it genuinely measures is that the two bits reach four DISTINCT words
(surjectivity and injectivity), and that half stays valid.

## The fact, and why it is DATA here

The words are upstream's: `Bits::S8..S64` in `zenoh-protocol`'s
`core/resolution.rs`, paired with the discriminants `U8 = 0b00 .. U64 = 0b11`
by `Bits::to_str`. That source is machine-local -- a cargo registry or git
checkout -- so a gate that REQUIRED it would SKIP green on a clone that has
neither, which is the failure mode item 611 names for `ext_target` in the same
census table.

So the mapping is DATA here, BOUND to the router pin, and re-derivable:

  * `--check` needs no external input and runs in Layer C0 on every push. It
    binds `PIN` to `ZENOHD_VERSION`'s default in `scripts/build-zenohd.sh` and
    refuses when that has moved, so a pin bump cannot land without re-deriving
    this. Then it holds BOTH in-tree populations to the mapping.
  * `--derive` re-derives it from upstream's own `resolution.rs` wherever that
    is on this machine. Absent input SKIPs unless `--require`.

⚠ NO LANE CARRIES `--derive --require` TODAY, and that is measured rather than
an oversight: nothing in `scripts/` provisions the zenoh PROTOCOL source.
`build-zenohd.sh` reaches a cargo git checkout or crates.io and leaves a built
binary, not a source tree this gate can name. Arming a flag no job can turn on
is what `decline_arming_gate.py` refuses, so the handle is not invented. The pin
binding is what carries the ratchet in the meantime.

## The two in-tree populations, both derived

  1. `sn_res_word`'s own match arms, parsed out of `dissect.rs`. Every code the
     function answers must map to the word this file pins, and every word this
     file pins must be answered -- BOTH directions, so neither a renamed word
     nor a dropped arm passes.
  2. the zenohd interop lane's `(word, code)` constant PAIRS. That lane spells
     two of the four and states each one's wire code beside it; both pairs must
     agree with the mapping. This is what turns item 611's second residue -- "a
     prose line joins the constants to the function" -- into a predicate.

An empty population on either side is a FAIL, not a pass: a parser that stopped
parsing looks exactly like a file with nothing in it.

## What this does NOT claim

That every word has a WIRE witness. Two do: the interop lane drives a genuine
zenohd at `"16bit"` and `"32bit"`. `"8bit"` and `"64bit"` are held to upstream's
SPELLING and CODE, which is what item 611's second and third conditions ask for,
and not to a router that answered them. Widening that lane means two more arms,
and an arm here is a zenohd, a pico `z_sub` and a relay per run -- named rather
than implied.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The router pin this mapping was derived at. Bound below to the one place that
# states it, on `zenoh_c_archive_arm.py`'s rule: a constant nobody can catch
# drifting is a constant that drifts.
PIN = "1.10.0"
BUILD_ZENOHD = "scripts/build-zenohd.sh"

# code -> word, from `Bits`'s discriminants and `Bits::to_str`.
WORDS = {0b00: "8bit", 0b01: "16bit", 0b10: "32bit", 0b11: "64bit"}

DISSECT = "crates/wz-session-core/src/dissect.rs"
INTEROP = "crates/wz-integration-tests/tests/wz_negotiated_axes_zenohd_interop.rs"

# The upstream file this mapping comes from, cited in the anchored form the
# citation gate asks for: `commons/zenoh-protocol/src/core/resolution.rs`
# @ `const S8: &'static str`. Assembled from segments rather than written as one
# literal because a second spelling of the same path would be a second citation,
# and this one is a path the program OPENS rather than a claim about upstream.
UPSTREAM_REL = pathlib.Path("commons", "zenoh-protocol", "src", "core",
                            "resolution.rs")

FN_RE = re.compile(r"fn sn_res_word\(.*?\)\s*->\s*&'static str\s*\{(?P<body>.*?)\n\}",
                   re.S)
ARM_RE = re.compile(r"(?P<code>0b[01]{1,8}|_)\s*=>\s*\"(?P<word>[^\"]+)\"")
CONST_STR_RE = re.compile(r"^const (?P<name>[A-Z0-9_]+):\s*&str\s*=\s*\"(?P<val>[^\"]+)\";",
                          re.M)
CONST_U8_RE = re.compile(r"^const (?P<name>[A-Z0-9_]+):\s*u8\s*=\s*(?P<val>\d+);", re.M)
PIN_RE = re.compile(r'^ZENOHD_VERSION="\$\{ZENOHD_VERSION:-(?P<v>[^}"]+)\}"', re.M)


def pinned_router_version(text: str) -> str | None:
    m = PIN_RE.search(text)
    return m.group("v") if m else None


def wz_mapping(text: str) -> dict[int, str]:
    """`sn_res_word`'s own answer, code -> word, parsed from its match arms.

    The `_` arm is the remaining code rather than a wildcard over all of them:
    the match is on `code & 0b11`, so three literal arms leave exactly one.
    """
    fn = FN_RE.search(text)
    if not fn:
        return {}
    out: dict[int, str] = {}
    catch_all: str | None = None
    for arm in ARM_RE.finditer(fn.group("body")):
        if arm.group("code") == "_":
            catch_all = arm.group("word")
        else:
            out[int(arm.group("code"), 2)] = arm.group("word")
    if catch_all is not None:
        rest = [c for c in range(4) if c not in out]
        if len(rest) != 1:
            return {}
        out[rest[0]] = catch_all
    return out


def interop_pairs(text: str) -> list[tuple[str, str, int]]:
    """`(name, word, code)` for each `*_RESOLUTION` / `*_RES_CODE` constant pair."""
    words = {m.group("name"): m.group("val") for m in CONST_STR_RE.finditer(text)}
    codes = {m.group("name"): int(m.group("val")) for m in CONST_U8_RE.finditer(text)}
    out = []
    for name, word in words.items():
        if not name.endswith("_RESOLUTION"):
            continue
        code_name = name[: -len("_RESOLUTION")] + "_RES_CODE"
        if code_name in codes:
            out.append((name, word, codes[code_name]))
    return out


def upstream_mapping(path: pathlib.Path) -> dict[int, str]:
    """`Bits`'s discriminants joined to its `S*` constants through `to_str`."""
    text = path.read_text(encoding="utf-8")
    variants = {m.group("v"): int(m.group("bits"), 2) for m in
                re.finditer(r"(?P<v>U\d+)\s*=\s*(?P<bits>0b[01]{2})", text)}
    consts = {m.group("c"): m.group("word") for m in
              re.finditer(r"const (?P<c>S\d+):\s*&'static str\s*=\s*\"(?P<word>[^\"]+)\"",
                          text)}
    to_str = dict(re.findall(r"Bits::(U\d+)\s*=>\s*Self::(S\d+)", text))
    out: dict[int, str] = {}
    for variant, code in variants.items():
        const = to_str.get(variant)
        if const and const in consts:
            out[code] = consts[const]
    return out


def upstream_source() -> pathlib.Path | None:
    """Upstream's `resolution.rs`, wherever this machine keeps it."""
    env = os.environ.get("WZ_ZENOH_SRC")
    roots: list[pathlib.Path] = []
    if env:
        roots.append(pathlib.Path(env))
    roots.append(pathlib.Path.home() / "zenoh-ref")
    for root in roots:
        cand = root / UPSTREAM_REL
        if cand.is_file():
            return cand
    reg = pathlib.Path.home() / ".cargo" / "registry" / "src"
    for cand in sorted(reg.glob(f"*/zenoh-protocol-{PIN}/src/core/resolution.rs")):
        return cand
    checkouts = pathlib.Path.home() / ".cargo" / "git" / "checkouts"
    for cand in sorted(checkouts.glob(f"zenoh-*/*/{UPSTREAM_REL}")):
        return cand
    return None


def check_all(dissect_text: str, interop_text: str,
              pin_text: str) -> tuple[int, list[str], list[str]]:
    """The whole verdict, over TEXT, so a mutation can drive the shipped path.

    Returns `(rc, report, failures)`. `cmd_check` reads the three files and
    prints what comes back; the selftest hands it mutated copies of those same
    files, which is the difference between grading the gate and grading a
    restatement of it.
    """
    rc = 0
    report: list[str] = []
    fail: list[str] = []

    stated = pinned_router_version(pin_text)
    if stated is None:
        fail.append(f"  sn-res-words FAIL: could not read ZENOHD_VERSION's default "
                    f"out of\n    {BUILD_ZENOHD}. The mapping is bound to the router "
                    f"pin, and a\n    binding whose other end cannot be read is not a "
                    f"binding.")
        rc = 1
    elif stated != PIN:
        fail.append(f"  sn-res-words FAIL: this file pins `{PIN}` and "
                    f"{BUILD_ZENOHD} says\n    `{stated}`. Re-derive the words from "
                    f"that release (`--derive`)\n    and move PIN in the same commit "
                    f"-- a mapping carried across a pin\n    bump is one nobody "
                    f"re-read.")
        rc = 1

    wz = wz_mapping(dissect_text)
    if not wz:
        fail.append(f"  sn-res-words FAIL: no `sn_res_word` match arm was parsed out "
                    f"of\n    {DISSECT}. That is the reader having stopped reading, "
                    f"not the\n    function having no answers -- a population of zero "
                    f"is not a pass.")
        rc = 1
    else:
        for code in sorted(set(WORDS) | set(wz)):
            mine, theirs = WORDS.get(code), wz.get(code)
            if mine == theirs:
                continue
            rc = 1
            fail.append(f"  sn-res-words FAIL: code {code:#04b} is `{theirs}` in\n"
                        f"    {DISSECT} and `{mine}` here. These are upstream's "
                        f"spellings;\n    fix the one that drifted, and if upstream "
                        f"moved, `--derive` first.")

    pairs = interop_pairs(interop_text)
    if not pairs:
        fail.append(f"  sn-res-words FAIL: no `<NAME>_RESOLUTION` / "
                    f"`<NAME>_RES_CODE`\n    constant pair was parsed out of "
                    f"{INTEROP}. That lane is what gives\n    two of these words a "
                    f"WIRE witness; a reader that finds none of\n    them has stopped "
                    f"reading.")
        rc = 1
    for name, word, code in pairs:
        if WORDS.get(code) != word:
            rc = 1
            fail.append(f"  sn-res-words FAIL: {name} is `{word}` with code {code}, "
                        f"and\n    this mapping says code {code} is "
                        f"`{WORDS.get(code)}`. The lane feeds\n    that spelling to a "
                        f"genuine zenohd, so the pair has to be\n    upstream's.")

    # ⚠ The summary must not out-claim the verdict. Printed unconditionally it
    # said "N arm(s) agree" beside its own FAIL line, which is the R2274 shape:
    # a reading is worth only what it can discriminate, and a reader scanning a
    # CI log would take "agree" and hunt the failure somewhere else.
    if rc == 0:
        report.append(f"  sn-res-words: {len(WORDS)} word(s) at router pin {PIN}; "
                      f"{len(wz)} `sn_res_word` arm(s) agree; "
                      f"{len(pairs)} interop (word, code) pair(s) checked "
                      f"({', '.join(n for n, _, _ in pairs)})")
    else:
        report.append(f"  sn-res-words: READ {len(WORDS)} word(s) at router pin "
                      f"{PIN}, {len(wz)} `sn_res_word` arm(s) and {len(pairs)} "
                      f"interop pair(s); the FAIL line(s) above say which "
                      f"disagreed. This line is not a pass.")
    return rc, report, fail


def cmd_check() -> int:
    rc, report, fail = check_all(
        (ROOT / DISSECT).read_text(encoding="utf-8"),
        (ROOT / INTEROP).read_text(encoding="utf-8"),
        (ROOT / BUILD_ZENOHD).read_text(encoding="utf-8"),
    )
    for line in fail:
        print(line, file=sys.stderr)
    for line in report:
        print(line)
    return rc


def cmd_derive(require: bool) -> int:
    src = upstream_source()
    if src is None:
        if require:
            print("  sn-res-words FAIL -- required, and no zenoh-protocol source was\n"
                  "    found (set WZ_ZENOH_SRC, or keep a checkout at ~/zenoh-ref).",
                  file=sys.stderr)
            return 1
        print("  sn-res-words SKIP -- no zenoh-protocol source on this machine; "
              "the pin binding is what holds the mapping here")
        return 0
    theirs = upstream_mapping(src)
    if not theirs:
        print(f"  sn-res-words FAIL: {src} parsed to NO (code, word) pair. Upstream\n"
              f"    may have restructured `Bits`; read it before moving anything.",
              file=sys.stderr)
        return 1
    rc = 0
    for code in sorted(set(WORDS) | set(theirs)):
        if WORDS.get(code) != theirs.get(code):
            rc = 1
            print(f"  sn-res-words FAIL: upstream says code {code:#04b} is "
                  f"`{theirs.get(code)}` and this file says `{WORDS.get(code)}`.\n"
                  f"    Upstream is the fact; move WORDS and re-run `--check`.",
                  file=sys.stderr)
    print(f"  sn-res-words: upstream at {src} carries {len(theirs)} (code, word) "
          f"pair(s), all matching" if rc == 0 else
          f"  sn-res-words: read upstream at {src}")
    return rc


# ─── selftest ────────────────────────────────────────────────────────────────

_GOOD_FN = ('fn sn_res_word(code: u8) -> &\'static str {\n'
            '    match code & 0b11 {\n'
            '        0b00 => "8bit",\n'
            '        0b01 => "16bit",\n'
            '        0b10 => "32bit",\n'
            '        _ => "64bit",\n'
            '    }\n'
            '}\n')

_GOOD_INTEROP = ('const NON_DEFAULT_RESOLUTION: &str = "16bit";\n'
                 'const NON_DEFAULT_RES_CODE: u8 = 1;\n'
                 'const DEFAULT_RESOLUTION: &str = "32bit";\n'
                 'const DEFAULT_RES_CODE: u8 = 2;\n')

_GOOD_UPSTREAM = ('pub enum Bits {\n'
                  '    U8 = 0b00,\n    U16 = 0b01,\n'
                  '    U32 = 0b10,\n    U64 = 0b11,\n}\n'
                  'impl Bits {\n'
                  '    const S8: &\'static str = "8bit";\n'
                  '    const S16: &\'static str = "16bit";\n'
                  '    const S32: &\'static str = "32bit";\n'
                  '    const S64: &\'static str = "64bit";\n'
                  '    pub const fn to_str(self) -> &\'static str {\n'
                  '        match self {\n'
                  '            Bits::U8 => Self::S8,\n'
                  '            Bits::U16 => Self::S16,\n'
                  '            Bits::U32 => Self::S32,\n'
                  '            Bits::U64 => Self::S64,\n'
                  '        }\n    }\n}\n')


def selftest(tmp: pathlib.Path) -> int:
    passed = failed = 0

    def case(name: str, ok: bool) -> None:
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1
            print(f"  sn-res-words SELFTEST `{name}` FAILED", file=sys.stderr)

    case("the shipped function maps all four codes",
         wz_mapping(_GOOD_FN) == WORDS)
    case("a renamed word is a different mapping",
         wz_mapping(_GOOD_FN.replace('"32bit"', '"32bits"')) != WORDS)
    case("a dropped arm leaves the catch-all ambiguous, so nothing is claimed",
         wz_mapping(_GOOD_FN.replace('        0b01 => "16bit",\n', "")) == {})
    case("a function this reader cannot find yields NO mapping, not a pass",
         wz_mapping("fn something_else() {}") == {})

    case("the interop pairs are read whole",
         interop_pairs(_GOOD_INTEROP)
         == [("NON_DEFAULT_RESOLUTION", "16bit", 1),
             ("DEFAULT_RESOLUTION", "32bit", 2)])
    case("a spelling without its code constant is not a pair",
         interop_pairs('const LONE_RESOLUTION: &str = "8bit";\n') == [])
    case("a code that contradicts its spelling is still READ as the pair it is",
         interop_pairs(_GOOD_INTEROP.replace("DEFAULT_RES_CODE: u8 = 2",
                                             "DEFAULT_RES_CODE: u8 = 3"))
         == [("NON_DEFAULT_RESOLUTION", "16bit", 1),
             ("DEFAULT_RESOLUTION", "32bit", 3)])

    case("upstream's Bits joins discriminant to constant through to_str",
         upstream_mapping(_write(tmp, "up.rs", _GOOD_UPSTREAM)) == WORDS)
    case("an upstream that renamed a word is a different mapping",
         upstream_mapping(_write(tmp, "up2.rs",
                                 _GOOD_UPSTREAM.replace('"64bit"', '"64bits"')))
         != WORDS)
    case("an upstream this reader cannot parse yields NOTHING, not a pass",
         upstream_mapping(_write(tmp, "up3.rs", "pub enum Bits {}\n")) == {})

    case("the pin is read from the shell assignment",
         pinned_router_version('ZENOHD_VERSION="${ZENOHD_VERSION:-1.10.0}"\n')
         == "1.10.0")
    case("a pin line this reader cannot find is None, not a default",
         pinned_router_version("ZENOHD_VERSION=1.10.0\n") is None)

    # ── the verdict itself, over the SHIPPED files and mutations of them ──
    #
    # `check_all` is the function `--check` calls. Each mutation is one a round
    # could plausibly make, and each case pins the phrase its own arm produces:
    # a case that reds for a neighbour's reason is not a control.
    dis = (ROOT / DISSECT).read_text(encoding="utf-8")
    inter = (ROOT / INTEROP).read_text(encoding="utf-8")
    pin = (ROOT / BUILD_ZENOHD).read_text(encoding="utf-8")

    def verdict(d: str, i: str, p: str) -> tuple[int, str]:
        code, _, failures = check_all(d, i, p)
        return code, "\n".join(failures)

    rc0, _ = verdict(dis, inter, pin)
    case("the shipped tree passes", rc0 == 0)

    rc1, why = verdict(dis.replace('0b10 => "32bit"', '0b10 => "32bits"'),
                       inter, pin)
    case("a renamed word in sn_res_word reds",
         rc1 == 1 and "is `32bits` in" in why)

    rc2, why = verdict(dis.replace("fn sn_res_word", "fn sn_res_word_renamed"),
                       inter, pin)
    case("a function this gate cannot find reds rather than passing",
         rc2 == 1 and "no `sn_res_word` match arm was parsed" in why)

    rc3, why = verdict(dis, inter.replace('DEFAULT_RESOLUTION: &str = "32bit"',
                                          'DEFAULT_RESOLUTION: &str = "8bit"'), pin)
    case("an interop spelling that contradicts its code reds",
         rc3 == 1 and "DEFAULT_RESOLUTION is `8bit` with code 2" in why)

    rc4, why = verdict(dis, re.sub(r"^const [A-Z0-9_]+_RES(OLUTION|_CODE).*$", "",
                                   inter, flags=re.M), pin)
    case("an interop lane with no pair left reds",
         rc4 == 1 and "constant pair was parsed out of" in why)

    rc5, why = verdict(dis, inter,
                       pin.replace('ZENOHD_VERSION:-1.10.0',
                                   'ZENOHD_VERSION:-1.11.0'))
    case("a router pin that moved without re-deriving reds",
         rc5 == 1 and "and move PIN in the same commit" in why)

    if failed == 0:
        print(f"  sn-res-words: selftest passed ({passed} cases, both verdicts)")
    return 1 if failed else 0


def _write(tmp: pathlib.Path, name: str, text: str) -> pathlib.Path:
    p = tmp / name
    p.write_text(text, encoding="utf-8")
    return p


def main() -> int:
    ap = argparse.ArgumentParser(description="the four SN-resolution words")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--derive", action="store_true")
    ap.add_argument("--require", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if not (args.check or args.derive or args.selftest):
        ap.error("pass one of --check / --derive / --selftest")

    rc = 0
    if args.selftest:
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rc |= selftest(pathlib.Path(d))
    if args.check:
        rc |= cmd_check()
    if args.derive:
        rc |= cmd_derive(args.require)
    return rc


if __name__ == "__main__":
    sys.exit(main())
