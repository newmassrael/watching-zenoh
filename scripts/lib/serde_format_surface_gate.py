#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2362 (no register item) -- the Zenoh Serialization Format's TYPE SURFACE
must be derived from upstream, not listed by hand.

The citation is `no register item` in the sense `gate_provenance_lint.py` uses:
this gate closes the `ext-pubsub-serde-codec` atom, which lives in the store's
ATOM inventory rather than under a `debt-` id, so there is no carry number to
name. It is stated here rather than left to silence.

## Why a gate, and why this shape

`ext-pubsub-serde-codec` is a FORMAT re-implementation: wz's `serde_codec`
answers zenoh-ext's `serialization.rs` type for type. What a format codec owes
is therefore a POPULATION -- the set of types the format can carry -- and until
this gate the population lived in one place only: the atom's residual prose,
which named `[T; N]`, `Box<[T]>`, `Cow<[T]>`, `Cow<str>`, `ZBytes`,
`HashMap`/`HashSet`, the tuple arities and the bulk hooks. That list was
written by whoever last read the upstream file. It is a record of what someone
NOTICED, and `cargo test` cannot fail on a type that is simply absent -- an
unimplemented `Serialize` is a compile error only at a call site nobody wrote.

So the gate DERIVES both populations by parsing, with the SAME parser:

  * upstream: `zenoh-ext/src/serialization.rs` in the pinned checkout,
  * wz:       `crates/wz-session-core/src/serde_codec.rs`,

and compares. Five axes come out of that parse, each one a thing the format
surface is actually made of:

  1. `Serialize` / `Deserialize` impl targets, canonicalised to a head token.
  2. The `impl_num!` numeric type list.
  3. The tuple ARITIES the `impl_tuple!` invocation covers.
  4. The two traits' own method sets (the bulk hooks live here).
  5. `ZSerializer` / `ZDeserializer` public method sets (the streaming half
     lives here).

The canonicaliser is not a hand-written population: it is one function applied
to BOTH files, so a type upstream adds shows up on the upstream side with no
edit here. The only hand-written thing is the ALIAS table, and an alias is not
a skip -- it names the wz counterpart and the gate then REQUIRES that
counterpart to be present. `ZBytes` aliases to `Vec`, because wz's payload
container is `Vec<u8>`; if wz ever loses `impl Serialize for Vec<T>` the alias
fails with it.

## Population zero is a FAIL

Every axis refuses an empty upstream set. A parser that silently matched
nothing would report green over a file it could not read, which is the failure
mode this tree has paid for repeatedly. `--selftest` drives each floor on its
own: an upstream fixture with each axis emptied in turn must FAIL, and the
full fixture must pass.

## Exit codes

  0  every upstream element is answered
  1  something upstream carries has no wz counterpart, or a floor is empty
  2  the inputs could not be READ (no pinned checkout, or a missing file) --
     distinguished from 1 because a gate that cannot read its input must not
     report a verdict about the tree.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The wz side. One file: the codec is a single module by construction.
WZ_REL = "crates/wz-session-core/src/serde_codec.rs"

#: The upstream side, relative to the pinned zenoh checkout root.
UPSTREAM_REL = "zenoh-ext/src/serialization.rs"

#: Upstream element -> the wz element that answers it. An alias is NOT a skip:
#: the gate requires the RIGHT-HAND side to be present in wz's own derived set,
#: so an alias can fail exactly like a missing impl can.
#:
#: `ZBytes` -- zenoh's payload container. wz's is `Vec<u8>` (`Sample.payload`),
#: and upstream's `impl Serialize for ZBytes` writes a `VarInt` length then the
#: raw bytes, which is what `impl Serialize for Vec<T>` writes at `T = u8`.
#:
#: `deserialize_n_uninit` -- upstream carries a second read hook over
#: `MaybeUninit` because `std::io::Read` can only fill initialised memory (its
#: own comment says so). wz reads from a borrowed slice, so `deserialize_n`
#: builds the run directly and subsumes both.
TYPE_ALIASES = {"ZBytes": "Vec"}
METHOD_ALIASES = {"deserialize_n_uninit": "deserialize_n"}

#: An impl head starts at a line-leading `impl` and ends at the first `{` --
#: neither a generic parameter list nor a `where` clause can contain a brace,
#: so that boundary is exact, and it is what lets a head SPAN LINES. It has to:
#: `rustfmt` breaks a long head before `for`, and the first draft of this gate
#: read only single-line heads and therefore reported `Deserialize for HashMap`
#: missing while the impl was right there.
_IMPL_START = re.compile(r"^impl\b", re.MULTILINE)
_FOR_SPLIT = re.compile(r"\bfor\b")


def _strip_where(text: str) -> str:
    """Drop a trailing `where` clause from an impl head."""
    m = re.search(r"\bwhere\b", text)
    return text[: m.start()] if m else text


def _impl_heads(src: str):
    """Yield each impl head, whitespace-collapsed, brace excluded."""
    for m in _IMPL_START.finditer(src):
        brace = src.find("{", m.end())
        if brace == -1:
            continue
        yield " ".join(src[m.end() : brace].split())


def canonical_type(raw: str) -> str | None:
    """Canonicalise an impl target to a head token.

    ONE function, applied to both trees, so the comparison cannot drift by
    dialect. Returns `None` for a target that is not part of the format
    surface (a tuple -- those are graded by arity -- or a blanket `&T`).
    """
    t = _strip_where(raw).strip().rstrip("{").strip()
    if not t:
        return None
    # `(T0, T1,)` and the macro's `($($ty,)*)` -- arity axis, not this one.
    if t.startswith("("):
        return None
    if t.startswith("&"):
        return "ref"
    if t.startswith("["):
        return "array" if ";" in t else "slice"
    head = re.match(r"[A-Za-z_][A-Za-z0-9_]*", t)
    if head is None:
        return None
    name = head.group(0)
    if name == "Cow":
        inner = t[t.find("<") + 1 :]
        # `Cow<'a, [T]>` vs `Cow<'_, str>`.
        return "cow_slice" if "[" in inner else "cow_str"
    if name == "Box":
        return "box_slice" if "[" in t else "box"
    if name == "VarInt":
        return "VarInt"
    return name


def parse_impls(src: str) -> tuple[set[str], set[str]]:
    """Return (serialize targets, deserialize targets) as canonical tokens."""
    ser: set[str] = set()
    de: set[str] = set()
    for head in _impl_heads(src):
        head = _strip_where(head)
        # Skip the generic parameter list before splitting on `for`: a bound
        # like `T: Iterator<Item = for<'a> fn(&'a u8)>` would otherwise split
        # in the wrong place.
        rest = head
        if rest.startswith("<"):
            depth = 0
            for i, ch in enumerate(rest):
                if ch == "<":
                    depth += 1
                elif ch == ">":
                    depth -= 1
                    if depth == 0:
                        rest = rest[i + 1 :]
                        break
        parts = _FOR_SPLIT.split(rest, maxsplit=1)
        if len(parts) != 2:
            continue
        trait, target = parts[0].strip(), parts[1]
        token = canonical_type(target)
        if token is None:
            continue
        if trait.startswith("Serialize"):
            ser.add(token)
        elif trait.startswith("Deserialize"):
            de.add(token)
    return ser, de


def parse_impl_num(src: str) -> set[str]:
    """The numeric type list the `impl_num!` invocation covers."""
    m = re.search(r"^impl_num!\((?P<args>[^)]*)\)", src, re.MULTILINE)
    if m is None:
        return set()
    return {a.strip() for a in m.group("args").split(",") if a.strip()}


def parse_tuple_arities(src: str) -> set[int]:
    """The tuple arities the file's `impl_tuple!` usage covers.

    Upstream writes ONE invocation whose macro recursion emits every arity from
    zero up to the invocation's length. wz writes one invocation per arity and
    spells arity zero as a plain `impl Serialize for ()`. Both dialects are read
    here, so the two sides are comparable without either being rewritten.
    """
    arities: set[int] = set()
    lengths = []
    for args in re.findall(r"impl_tuple!\((?P<args>.*?)\)", src, re.DOTALL):
        stripped = args.strip()
        # `impl_tuple!(@ ...)` arms are the macro's own recursion, not a
        # request for an arity. Reading them as invocations is what made the
        # first draft report an upstream population of two.
        if stripped.startswith("@"):
            continue
        n = len([a for a in stripped.split(",") if a.strip()])
        if n:
            lengths.append(n)
    if not lengths:
        return arities
    if re.search(r"impl_tuple!\(\s*@", src, re.DOTALL):
        # The RECURSIVE dialect (upstream's): one invocation, and the macro
        # emits every arity from zero up to its length.
        arities.update(range(0, max(lengths) + 1))
    else:
        # The per-arity dialect (wz's): one invocation per arity, with the
        # empty tuple spelled as a plain impl.
        arities.update(lengths)
    if re.search(r"^impl\s+Serialize\s+for\s+\(\)\s*\{", src, re.MULTILINE):
        arities.add(0)
    return arities


def parse_trait_methods(src: str, trait: str) -> set[str]:
    """The method names declared inside `pub trait <trait>`."""
    m = re.search(
        r"^pub trait " + re.escape(trait) + r"[^\n{]*\{", src, re.MULTILINE
    )
    if m is None:
        return set()
    depth = 0
    start = m.end() - 1
    for i in range(start, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                body = src[start : i + 1]
                return set(re.findall(r"\bfn\s+([a-z_][a-z0-9_]*)", body))
    return set()


def parse_inherent_methods(src: str, type_name: str) -> set[str]:
    """The `pub fn` names on `impl [<generics>] <type_name>[<args>]`."""
    pattern = (
        r"^impl(?:<[^\n]*?>)?\s+" + re.escape(type_name) + r"(?:<[^\n{]*?>)?\s*\{"
    )
    m = re.search(pattern, src, re.MULTILINE)
    if m is None:
        return set()
    depth = 0
    start = m.end() - 1
    for i in range(start, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                body = src[start : i + 1]
                return set(re.findall(r"\bpub fn\s+([a-z_][a-z0-9_]*)", body))
    return set()


def upstream_root() -> Path | None:
    """The pinned zenoh checkout, through this tree's own discovery.

    Reuses `upstream_citation_anchor_gate.upstream_root()` so the two gates can
    never disagree about WHICH checkout is the pin.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import upstream_citation_anchor_gate as anchor
    except Exception:
        return None
    try:
        root = anchor.upstream_root()
    except Exception:
        return None
    return Path(root) if root else None


class Axis:
    """One derived population and its verdict."""

    def __init__(self, name, upstream, wz, aliases=None, render=str):
        self.name = name
        self.upstream = upstream
        self.wz = wz
        self.aliases = aliases or {}
        self.render = render

    def missing(self):
        out = []
        for item in sorted(self.upstream, key=self.render):
            want = self.aliases.get(item, item)
            if want not in self.wz:
                out.append((item, want))
        return out


def grade(upstream_src: str, wz_src: str) -> tuple[int, list[str]]:
    """Return (exit code, report lines)."""
    lines: list[str] = []
    up_ser, up_de = parse_impls(upstream_src)
    wz_ser, wz_de = parse_impls(wz_src)

    axes = [
        Axis("Serialize impl targets", up_ser, wz_ser, TYPE_ALIASES),
        Axis("Deserialize impl targets", up_de, wz_de, TYPE_ALIASES),
        Axis("impl_num! numeric types", parse_impl_num(upstream_src),
             parse_impl_num(wz_src)),
        Axis("tuple arities", parse_tuple_arities(upstream_src),
             parse_tuple_arities(wz_src), render=lambda n: f"{n:03d}"),
        Axis("Serialize trait methods", parse_trait_methods(upstream_src, "Serialize"),
             parse_trait_methods(wz_src, "Serialize"), METHOD_ALIASES),
        Axis("Deserialize trait methods",
             parse_trait_methods(upstream_src, "Deserialize"),
             parse_trait_methods(wz_src, "Deserialize"), METHOD_ALIASES),
        Axis("ZSerializer public methods",
             parse_inherent_methods(upstream_src, "ZSerializer"),
             parse_inherent_methods(wz_src, "ZSerializer")),
        Axis("ZDeserializer public methods",
             parse_inherent_methods(upstream_src, "ZDeserializer"),
             parse_inherent_methods(wz_src, "ZDeserializer")),
    ]

    failed = False
    for axis in axes:
        if not axis.upstream:
            lines.append(
                f"  serde-format-surface: FAIL -- the upstream population for "
                f"`{axis.name}` is EMPTY. The parser read nothing, so this is a "
                f"claim about the READER, not about wz."
            )
            failed = True
            continue
        missing = axis.missing()
        if missing:
            failed = True
            for item, want in missing:
                via = "" if item == want else f" (via alias -> `{want}`)"
                lines.append(
                    f"  serde-format-surface: FAIL -- upstream carries "
                    f"`{item}` on axis `{axis.name}`{via} and wz does not."
                )
        lines.append(
            f"  serde-format-surface: {axis.name}: "
            f"{len(axis.upstream)} upstream / {len(axis.wz)} wz -- "
            f"{'MISSING ' + str(len(missing)) if missing else 'covered'}"
        )
    return (1 if failed else 0), lines


#: A synthetic upstream that exercises every axis, used only by `--selftest`.
FIXTURE_UPSTREAM = """
pub trait Serialize {
    fn serialize(&self, serializer: &mut ZSerializer);
    fn serialize_n(slice: &[Self], serializer: &mut ZSerializer) where Self: Sized {}
}
pub trait Deserialize: Sized {
    fn deserialize(deserializer: &mut ZDeserializer) -> Result<Self, E>;
    fn deserialize_n(in_place: &mut [Self], d: &mut ZDeserializer) -> R {}
    fn deserialize_n_uninit<'a>(in_place: &'a mut [MaybeUninit<Self>]) -> R {}
}
impl ZSerializer {
    pub fn new() -> Self {}
    pub fn serialize<T: Serialize>(&mut self, t: T) {}
    pub fn serialize_iter<T: Serialize, I>(&mut self, iter: I) {}
    pub fn finish(self) -> ZBytes {}
}
impl<'a> ZDeserializer<'a> {
    pub fn new(zbytes: &'a ZBytes) -> Self {}
    pub fn done(&self) -> bool {}
    pub fn deserialize<T: Deserialize>(&mut self) -> R {}
    pub fn deserialize_iter<'b, T: Deserialize>(&'b mut self) -> R {}
}
impl Serialize for ZBytes {}
impl Serialize for bool {}
impl Deserialize for bool {}
impl<T: Serialize> Serialize for [T] {}
impl<T: Serialize, const N: usize> Serialize for [T; N] {}
impl<T: Deserialize, const N: usize> Deserialize for [T; N] {}
impl<'a, T: Serialize + 'a> Serialize for Cow<'a, [T]> where [T]: ToOwned {}
impl Serialize for Cow<'_, str> {}
impl<T: Serialize> Serialize for Box<[T]> {}
impl<T: Deserialize> Deserialize for Box<[T]> {}
impl<T: Serialize> Serialize for Vec<T> {}
impl<T: Deserialize> Deserialize for Vec<T> {}
impl<T: Serialize> Serialize for HashSet<T> {}
impl<T: Deserialize> Deserialize for HashSet<T> {}
impl<T: Serialize> Serialize for BTreeSet<T> {}
impl<T: Deserialize> Deserialize for BTreeSet<T> {}
impl<K, V> Serialize for HashMap<K, V> {}
impl<K, V> Deserialize for HashMap<K, V> {}
impl<K, V> Serialize for BTreeMap<K, V> {}
impl<K, V> Deserialize for BTreeMap<K, V> {}
impl Serialize for str {}
impl Serialize for String {}
impl Deserialize for String {}
impl Serialize for VarInt<usize> {}
impl Deserialize for VarInt<usize> {}
impl_num!(i8, u8, f32);
impl_tuple!(T0 / 0, T1 / 1, T2 / 2);
"""


def selftest() -> int:
    """Drive both directions, and each floor emptied on its own."""
    wz_src = (REPO_ROOT / WZ_REL).read_text(encoding="utf-8")
    rows: list[tuple[str, int, int]] = []

    rc, _ = grade(FIXTURE_UPSTREAM, wz_src)
    rows.append(("full fixture vs the live wz module", rc, 0))

    # Every floor emptied on its own: the gate must FAIL rather than report a
    # green over a population of zero.
    floors = {
        "no impls": re.sub(r"^impl .*$", "", FIXTURE_UPSTREAM, flags=re.MULTILINE),
        "no impl_num!": FIXTURE_UPSTREAM.replace("impl_num!(i8, u8, f32);", ""),
        "no impl_tuple!": FIXTURE_UPSTREAM.replace(
            "impl_tuple!(T0 / 0, T1 / 1, T2 / 2);", ""
        ),
        "no traits": re.sub(
            r"pub trait \w+[^{]*\{.*?\n\}", "", FIXTURE_UPSTREAM, flags=re.DOTALL
        ),
        "empty upstream": "",
    }
    for name, src in floors.items():
        rc, _ = grade(src, wz_src)
        rows.append((f"floor `{name}` must FAIL", rc, 1))

    # The reverse direction: an upstream that grows something wz lacks.
    grown = FIXTURE_UPSTREAM + "\nimpl Serialize for SomethingNew {}\n"
    rc, _ = grade(grown, wz_src)
    rows.append(("an upstream addition must FAIL", rc, 1))

    # And an ALIAS is not a skip: drop `Vec` from a wz copy and the `ZBytes`
    # alias must fail with it.
    wz_no_vec = wz_src.replace("impl<T: Serialize> Serialize for Vec<T> {", "impl<T: Serialize> Serialize for Nothing<T> {")
    rc, _ = grade(FIXTURE_UPSTREAM, wz_no_vec)
    rows.append(("an alias whose target is gone must FAIL", rc, 1))

    bad = 0
    for name, got, want in rows:
        ok = got == want
        bad += 0 if ok else 1
        print(
            f"  serde-format-surface selftest: {'ok  ' if ok else 'FAIL'} "
            f"{name} (rc={got}, want {want})"
        )
    if bad:
        print(f"  serde-format-surface: SELFTEST FAILED -- {bad} row(s)")
        return 1
    print(f"  serde-format-surface: selftest ok -- {len(rows)} row(s)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true",
                    help="drive the gate over a synthetic upstream, no checkout needed")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    wz_path = REPO_ROOT / WZ_REL
    if not wz_path.is_file():
        print(f"  serde-format-surface: FAIL -- wz source missing at {WZ_REL}")
        return 2
    root = upstream_root()
    if root is None:
        print(
            "  serde-format-surface: FAIL -- no pinned zenoh checkout is "
            "reachable, so NOTHING was graded. Provision one (build-zenohd.sh) "
            "or point ZENOHD_SRC at a checkout of the pinned tag."
        )
        return 2
    up_path = root / UPSTREAM_REL
    if not up_path.is_file():
        print(
            f"  serde-format-surface: FAIL -- the pinned checkout at {root} has "
            f"no {UPSTREAM_REL}, so the upstream population could not be read."
        )
        return 2

    rc, lines = grade(
        up_path.read_text(encoding="utf-8"), wz_path.read_text(encoding="utf-8")
    )
    for line in lines:
        print(line)
    print(f"  serde-format-surface: upstream = {up_path}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
