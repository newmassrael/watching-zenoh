#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2973 (no register item) — WHICH HOSTS A SURFACE RUNS ON IS UPSTREAM'S
ANSWER, AND WZ HAS TO GIVE THE SAME ONE, BUILD AND RUN.

## Why the citation says no item while the file answers for two

The two gaps this gate was written to carry are open-debt items 851 and 852,
which live in the half of the register that is not the store, so there is no
`debt-` id to cite -- the standing `upstream_link_axis_gate.py` is in for item
593. Item 851 is BUILT (R2994: unixpipe is served on macOS, and `SERVE_GAPS` is
empty); item 852 is still named in full in `EXEC_GAPS` below, which is where a
reader grepping for it will land.

## What was wrong, measured at R2973

`platform-macos` and `platform-windows` claim wz runs on those hosts. The only
execution evidence was the `portability` job, and it ran ONE link: TCP. Nothing
said which host-restricted surfaces those hosts should carry, so nothing could
say what was missing, and five defects sat in that silence:

  * `transport-link-unixsock` compiled only on a Unix, yet every cfg site naming
    it named the feature alone. A Windows build that enabled it did not compile
    at all -- twelve errors against `x86_64-pc-windows-gnu` -- where upstream's
    crate declares its implementation under `target_family = "unix"` and simply
    serves nothing there.
  * `runtime-tokio-uring` did not compile off Linux either -- 54 errors, the
    `io-uring` crate itself, which sat in the host-independent dependency
    table. Upstream's `uring` puts its whole implementation under
    `target_os = "linux"` (`commons/zenoh-uring/src/lib.rs` @ `mod linux;`) and
    is inert elsewhere.
  * a vsock-only uring accessor in `stream_link.rs` named its feature and not
    the Linux host its one consumer lives on.
  * wz's unixpipe is `target_os = "linux"` while upstream's is `unix`: macOS is a
    host upstream runs that link on and wz does not (item 851).
  * the serial tests all open an `openpty` pair, which does not exist on
    Windows, so a Windows test build naming the feature did not compile, and
    upstream serves serial there (item 852 is the half that stays open: nothing
    can EXECUTE a serial link on a Windows runner).

The population is the thing that was missing, so the population is derived.

## Four arms

  1. UPSTREAM, from the pin. A LINK is served on a host when BOTH the registry's
     `pub use zenoh_link_<crate> as ..` in `io/zenoh-link/src/lib.rs` @
     `pub use zenoh_link_tcp as tcp;` and every
     `mod` the crate's own `src/lib.rs` declares are compiled there. The two are
     read together because each gates alone: unixsock is gated in the registry,
     unixpipe only inside its crate (`#[cfg(unix)] mod unix;`). A non-link
     FEATURE (`RUNTIME_FEATURES`) is served where every `mod` of the upstream
     crate it mirrors is compiled.
  2. WZ, from the cfg on the surface's `pub mod` in wz-runtime-tokio's
     `lib.rs`, with every feature on (the question is the HOST, not the
     feature). The link population is `pub enum LinkKind`, read by
     `upstream_link_axis_gate`, and `RUNTIME_LINKS` must cover it exactly. The
     two matrices must agree host by host, except where `SERVE_GAPS` names the
     debt -- and a gap row whose two sides have come to agree is a finding too,
     so a closed gap cannot linger as a stated one.
  3. SITES. In every workspace crate whose features REACH a host-restricted
     wz-runtime-tokio feature (cargo's own feature graph, through `dep/feat`
     forwards), naming such a feature must be INERT on a host that does not
     serve it -- upstream's rule. "Because of the feature" is measured, not
     guessed: each site's full predicate -- its file's context, every enclosing
     gated item, and itself -- is evaluated with every feature on, and again
     with that one feature off. On an unserved host the two must agree: a site
     that switches ON there compiles against a module that is not there (the
     twelve errors), one that switches OFF loses its fallback and leaves that
     host with neither arm.
  4. EVIDENCE. For macOS and Windows -- the two hosts no other lane runs -- each
     link wz serves names the integration-test targets that exercise it, and the
     target's own cfg must select at least one non-ignored test on that host
     under the leg's features. `--run <host>` executes the leg in ONE cargo
     invocation (one build of the union feature set) and requires every target
     to report a passing count of at least one. `EXEC_GAPS` names what cannot
     run there, and a gap whose target now selects a test is stale.

The three graded hosts are the CI runners': Linux and Windows on x86_64, macOS
on aarch64 (`macos-latest`). Linux is the reference host: its links are graded
by the lanes that own each (C1al, C1ab, the E-layer interop), so no Linux leg is
declared here.

## What this does NOT see

A dependency API that exists only on some hosts (`SerialStream::pair` is
`#[cfg(unix)]` inside tokio-serial). No cfg in this tree names it, so arm 3
cannot; arm 4's `--run` on the real host is what catches it, which is why the
leg compiles every link it lists rather than only the ones it can execute.
Nor does it see a site inside a `macro_rules!` body: that is a template until
it expands.

## Arms by lane

`--selftest` needs nothing. `--check` grades arms 2-4 everywhere and arm 1
where a checkout of the pinned zenoh is reachable, and SAYS so when it is not;
`--require` turns that into a FAIL, which is how Layer Z runs it.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import upstream_link_axis_gate as axis  # noqa: E402  the LinkKind population + pin root

ROOT = pathlib.Path(__file__).resolve().parents[2]

HOSTS = ("linux", "macos", "windows")
ALL_HOSTS = frozenset(HOSTS)
UNIX_HOSTS = frozenset({"linux", "macos"})
#: The architecture each graded host is, as the CI runners are.
HOST_ARCH = {"linux": "x86_64", "macos": "aarch64", "windows": "x86_64"}
#: The hosts this gate carries an execution leg for; see the module docstring.
LEG_HOSTS = ("macos", "windows")

RUNTIME = "wz-runtime-tokio"
RUNTIME_LIB = pathlib.Path("crates/wz-runtime-tokio/src/lib.rs")
RUNTIME_TESTS = pathlib.Path("crates/wz-runtime-tokio/tests")
#: Upstream's link registry, joined by part as the sibling gates join theirs: this
#: is a path to READ, not a claim about upstream, so it is not a citation.
REGISTRY = pathlib.Path("io") / "zenoh-link" / "src" / "lib.rs"

#: wz kind -> (its wz-runtime-tokio feature, the `pub mod` that implements it).
#: Knowledge, not population: the population is `pub enum LinkKind`, and this
#: must cover it exactly.
RUNTIME_LINKS: dict[str, tuple[str, str]] = {
    "Tcp": ("transport-link-tcp", "link_pipeline"),
    "Udp": ("transport-link-udp", "udp_pipeline"),
    "UdpReliable": ("transport-link-udp-reliable", "udp_reliable_pipeline"),
    "Tls": ("transport-link-tls", "tls_pipeline"),
    "Quic": ("transport-link-quic", "quic_pipeline"),
    "QuicDatagram": ("transport-link-quic-datagram", "quic_datagram_pipeline"),
    "Serial": ("transport-link-serial", "serial_pipeline"),
    "Unixpipe": ("transport-link-unixpipe", "unixpipe_pipeline"),
    "UnixsockStream": ("transport-link-unixsock", "unixsock_pipeline"),
    "Vsock": ("transport-link-vsock", "vsock_pipeline"),
    "Ws": ("transport-link-ws", "ws_pipeline"),
}

#: Host-restricted wz-runtime-tokio features that are not links -> (feature, its
#: `pub mod`, the upstream crate it mirrors). A DECLARED list, because "this wz
#: feature mirrors that upstream crate" is knowledge no manifest states; what
#: keeps it honest is arm 1, which reads the crate's own gates at the pin.
RUNTIME_FEATURES: dict[str, tuple[str, str, str]] = {
    "Uring": ("runtime-tokio-uring", "uring", "commons/zenoh-uring"),
}

#: (surface, host) where upstream serves it and wz does not -> (open-debt item,
#: why). Each row is a debt, never a design decision.
#:
#: Empty since item 851 was built (R2994): wz opened its FIFOs through tokio's
#: `pipe::OpenOptions::read_write`, which tokio compiles on Linux only, where
#: upstream opens them with std's `OpenOptions` (read + write + O_NONBLOCK) on
#: any Unix and drops only its advisory lock on macOS. wz now does the same, so
#: the gate derives unixpipe as served on macOS and a stale row here is a finding.
SERVE_GAPS: dict[tuple[str, str], tuple[int, str]] = {}

#: wz kind -> the wz-runtime-tokio integration-test targets that run it.
EVIDENCE: dict[str, tuple[str, ...]] = {
    "Tcp": ("accept_and_open_session", "connect_and_open_session"),
    "Udp": ("udp_seam_e2e",),
    "UdpReliable": ("udp_reliable_e2e",),
    "Tls": ("tls_e2e",),
    "Quic": ("quic_e2e",),
    "QuicDatagram": ("quic_datagram_e2e",),
    "Serial": ("serial_pty_e2e",),
    "Unixpipe": ("unixpipe_e2e",),
    "UnixsockStream": ("unixsock_e2e",),
    "Vsock": ("vsock_e2e",),
    "Ws": ("ws_e2e",),
}

#: (kind, host) that wz serves and BUILDS in the leg but no target can run
#: there -> (open-debt item, why).
EXEC_GAPS: dict[tuple[str, str], tuple[int, str]] = {
    ("Serial", "windows"): (
        852,
        "every serial witness opens an `openpty` pair (`SerialStream::pair`, "
        "`#[cfg(unix)]` in tokio-serial) and a Windows runner has no virtual "
        "COM pair, so the leg compiles the link there and executes none of it",
    ),
}


# ─── Rust text: comments and literals masked, offsets kept ──────────────────


def _ident_char(c: str) -> bool:
    return c.isalnum() or c == "_"


_RAW_OPEN = re.compile(r'(?:br|rb|r)(#*)"')


def mask(text: str, literals: bool = True) -> str:
    """`text` with every comment and every literal's body blanked to spaces.

    Newlines survive and nothing moves, so an offset found in the mask indexes
    the original. A `#[cfg(` inside a doc comment or a string is therefore not a
    site. `literals=False` blanks the comments only, which is the text a cfg
    predicate is PARSED from: its strings are its feature names, and a comment
    between two of its arms (config.rs carries one) is not part of it.
    """
    out = list(text)
    n = len(text)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    def blank_literal(a: int, b: int) -> None:
        if literals:
            blank(a, b)

    i = 0
    while i < n:
        c = text[i]
        if c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if c == "/" and text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue
        if c in "rb" and (i == 0 or not _ident_char(text[i - 1])):
            m = _RAW_OPEN.match(text, i)
            if m:
                close = '"' + m.group(1)
                j = text.find(close, m.end())
                j = n if j < 0 else j + len(close)
                blank_literal(m.end(), j - len(close))
                i = j
                continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank_literal(i + 1, j)
            i = j + 1
            continue
        if c == "'":
            if i + 1 < n and text[i + 1] == "\\":
                j = text.find("'", i + 3)
                j = n if j < 0 else j
                blank_literal(i + 1, j)
                i = j + 1
                continue
            if i + 2 < n and text[i + 2] == "'":
                blank_literal(i + 1, i + 2)
                i += 3
                continue
        i += 1
    return "".join(out)


# ─── cfg predicates ──────────────────────────────────────────────────────────


class UnknownCfg(ValueError):
    """A cfg atom this evaluator has no host answer for. Fail closed."""


_TOKEN = re.compile(
    r'\s*(?:(?P<id>[A-Za-z_][A-Za-z0-9_]*)|(?P<str>"(?:[^"\\]|\\.)*")|(?P<p>[(),=]))',
    re.S,
)


def _tokens(text: str, pos: int) -> Iterable[tuple[str, str, int]]:
    while True:
        m = _TOKEN.match(text, pos)
        if not m:
            raise ValueError(f"unreadable cfg predicate at offset {pos}")
        kind = m.lastgroup
        yield kind, m.group(kind), m.end()
        pos = m.end()


def parse_cfg(text: str, pos: int) -> tuple[tuple, int]:
    """Parse the predicate that starts at `pos` (just after `cfg(`).

    Returns (tree, offset just past the closing `)`). Trees are tuples:
    `("all"|"any"|"not", (args..))`, `("id", name)`, `("kv", key, value)`.
    """
    toks = _tokens(text, pos)
    look: list[tuple[str, str, int]] = []

    def peek() -> tuple[str, str, int]:
        if not look:
            look.append(next(toks))
        return look[0]

    def take() -> tuple[str, str, int]:
        t = peek()
        look.pop(0)
        return t

    def pred() -> tuple:
        kind, val, _ = take()
        if kind != "id":
            raise ValueError(f"cfg predicate expected a name, got {val!r}")
        if val in ("all", "any", "not") and peek()[1] == "(":
            take()
            args: list[tuple] = []
            while peek()[1] != ")":
                args.append(pred())
                if peek()[1] == ",":
                    take()
                elif peek()[1] != ")":
                    raise ValueError(f"cfg `{val}(..)` expected `,` or `)`")
            take()
            if val == "not" and len(args) != 1:
                raise ValueError("cfg `not(..)` takes exactly one predicate")
            return (val, tuple(args))
        if peek()[1] == "=":
            take()
            skind, sval, _ = take()
            if skind != "str":
                raise ValueError(f"cfg `{val} = ..` expected a string")
            return ("kv", val, sval[1:-1])
        return ("id", val)

    tree = pred()
    kind, val, end = take()
    if val != ")":
        raise ValueError(f"cfg predicate did not close, got {val!r}")
    return tree, end


#: Bare cfg names that are the same on every graded host. `test` is ON because
#: `cargo test` is the broadest compile of a crate; the doc-only names are off.
BARE = {"test": True, "debug_assertions": True, "doc": False, "docsrs": False, "miri": False}


def holds(tree: tuple, host: str, feat: Callable[[str], bool]) -> bool:
    tag = tree[0]
    if tag == "all":
        return all(holds(a, host, feat) for a in tree[1])
    if tag == "any":
        return any(holds(a, host, feat) for a in tree[1])
    if tag == "not":
        return not holds(tree[1][0], host, feat)
    if tag == "id":
        name = tree[1]
        if name == "unix":
            return host in UNIX_HOSTS
        if name == "windows":
            return host == "windows"
        if name in BARE:
            return BARE[name]
        raise UnknownCfg(name)
    key, value = tree[1], tree[2]
    if key == "feature":
        return feat(value)
    if key == "target_os":
        # A target_os that is none of the graded hosts (android, none, ...) is
        # simply false on all three -- not unknown.
        return host == value
    if key == "target_family":
        if value == "unix":
            return host in UNIX_HOSTS
        if value == "windows":
            return host == "windows"
        return False
    if key == "target_arch":
        return HOST_ARCH[host] == value
    if key == "target_pointer_width":
        return value == "64"
    raise UnknownCfg(f'{key} = "{value}"')


def hosts_of(preds: Iterable[tuple], feat: Callable[[str], bool]) -> frozenset[str]:
    preds = tuple(preds)
    return frozenset(h for h in HOSTS if all(holds(p, h, feat) for p in preds))


def features_named(tree: tuple) -> set[str]:
    if tree[0] in ("all", "any", "not"):
        out: set[str] = set()
        for a in tree[1]:
            out |= features_named(a)
        return out
    if tree[0] == "kv" and tree[1] == "feature":
        return {tree[2]}
    return set()


def render(tree: tuple) -> str:
    if tree[0] in ("all", "any", "not"):
        return f"{tree[0]}({', '.join(render(a) for a in tree[1])})"
    if tree[0] == "id":
        return tree[1]
    return f'{tree[1]} = "{tree[2]}"'


def everything(_feature: str) -> bool:
    return True


# ─── gated spans inside one file ─────────────────────────────────────────────

_ATTR = re.compile(r"#(!?)\[\s*cfg\s*\(")
_KEYWORD_ITEM = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?(?:fn|mod|impl|struct|enum|trait|const|static|type|use|"
    r"extern|unsafe|async|union|macro_rules|let)\b"
)
_MOD_DECL = re.compile(r"\bmod\s+(?:r#)?([A-Za-z_]\w*)\s*;")
_MOD_INLINE = re.compile(r"\bmod\s+(?:r#)?([A-Za-z_]\w*)\s*\{")
_PATH_ATTR = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')
_MACRO_RULES = re.compile(r"\bmacro_rules!\s*[A-Za-z_]\w*\s*([({\[])")


def _close_bracket(masked: str, i: int) -> int:
    """Offset just past the bracket that closes the one at `i`."""
    depth = 0
    for j in range(i, len(masked)):
        c = masked[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return j + 1
    return len(masked)


def _skip_attrs(masked: str, i: int) -> int:
    n = len(masked)
    while True:
        while i < n and masked[i].isspace():
            i += 1
        if masked.startswith("#[", i):
            i = _close_bracket(masked, i + 1)
            continue
        return i


def item_span(masked: str, i: int) -> tuple[int, int]:
    """The item an outer attribute ending at `i` gates.

    A keyword item (fn, mod, impl, ...) ends at its `;` or at the `}` closing
    its first top-level block. Anything else -- a match arm, a field, a variant,
    a statement -- ALSO ends at the first top-level `,`. Where that is too short
    (a struct pattern's braces) the span under-covers, which can only make a
    nested site LOUDER, never quieter: a context this gate fails to see is a
    context it does not credit.
    """
    start = _skip_attrs(masked, i)
    keyword = bool(_KEYWORD_ITEM.match(masked, start))
    depth = 0
    for j in range(start, len(masked)):
        c = masked[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return start, j
            depth -= 1
            if depth == 0 and c == "}":
                return start, j + 1
        elif depth == 0 and (c == ";" or (c == "," and not keyword)):
            return start, j + 1
    return start, len(masked)


def _block_rest(masked: str, i: int) -> tuple[int, int]:
    """From `i` to the end of the block enclosing it (an inner attribute's reach)."""
    depth = 0
    for j in range(i, len(masked)):
        c = masked[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i, j
            depth -= 1
    return i, len(masked)


@dataclass(frozen=True)
class Site:
    line: int
    tree: tuple
    span: tuple[int, int]
    #: `#![cfg(..)]`: it gates the rest of its block (the whole file at top level).
    inner: bool


def cfg_sites(text: str, masked: str) -> list[Site]:
    """Every cfg attribute that gates compiled code.

    One inside a `macro_rules!` body is a TEMPLATE (`feature = $feat` is not a
    predicate until the macro expands), so it is not a site.
    """
    code = mask(text, literals=False)
    templates = [
        (m.end() - 1, _close_bracket(masked, m.end() - 1)) for m in _MACRO_RULES.finditer(masked)
    ]
    sites: list[Site] = []
    for m in _ATTR.finditer(masked):
        if any(a < m.start() < b for a, b in templates):
            continue
        tree, end = parse_cfg(code, m.end())
        close = masked.find("]", end)
        if close < 0:
            raise ValueError("cfg attribute never closes")
        span = _block_rest(masked, close + 1) if m.group(1) else item_span(masked, close + 1)
        sites.append(Site(text.count("\n", 0, m.start()) + 1, tree, span, bool(m.group(1))))
    return sites


def context_at(sites: list[Site], pos: int) -> list[tuple]:
    return [s.tree for s in sites if s.span[0] <= pos < s.span[1]]


# ─── the module tree of a crate target ──────────────────────────────────────


@dataclass
class SourceFile:
    path: pathlib.Path
    text: str
    masked: str
    sites: list[Site]


def source(text: str, path: pathlib.Path) -> SourceFile:
    masked = mask(text)
    try:
        sites = cfg_sites(text, masked)
    except ValueError as e:
        raise ValueError(f"{path}: {e}") from e
    return SourceFile(path, text, masked, sites)


def load(path: pathlib.Path, cache: dict[pathlib.Path, SourceFile]) -> SourceFile:
    if path not in cache:
        cache[path] = source(path.read_text(encoding="utf-8"), path)
    return cache[path]


def _attr_run_start(masked: str, pos: int) -> int:
    """Walk back from `pos` over whitespace and complete `#[..]` groups."""
    i = pos
    while True:
        j = i
        while j > 0 and masked[j - 1].isspace():
            j -= 1
        if j > 0 and masked[j - 1] == "]":
            depth, k = 0, j - 1
            while k >= 0:
                if masked[k] == "]":
                    depth += 1
                elif masked[k] == "[":
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            if k > 0 and masked[k - 1] == "#":
                i = k - 1
                continue
        return i


def walk(
    root: pathlib.Path,
    read: Callable[[pathlib.Path], SourceFile],
    exists: Callable[[pathlib.Path], bool],
) -> tuple[list[tuple[SourceFile, tuple[tuple, ...]]], list[str]]:
    """Every file one crate target compiles, with the cfg context it is reached under."""
    out: list[tuple[SourceFile, tuple[tuple, ...]]] = []
    findings: list[str] = []
    seen: set[tuple[pathlib.Path, str]] = set()
    stack: list[tuple[pathlib.Path, tuple[tuple, ...], bool]] = [(root, (), True)]
    while stack:
        path, ctx, is_root = stack.pop()
        key = (path, repr(ctx))
        if key in seen:
            continue
        seen.add(key)
        src = read(path)
        out.append((src, ctx))
        inline = [
            (m.group(1), m.end() - 1, _close_bracket(src.masked, m.end() - 1))
            for m in _MOD_INLINE.finditer(src.masked)
        ]
        mod_root = is_root or path.name in ("lib.rs", "main.rs", "mod.rs")
        base = path.parent if mod_root else path.parent / path.stem
        for m in _MOD_DECL.finditer(src.masked):
            name = m.group(1)
            run = src.text[_attr_run_start(src.masked, m.start()) : m.start()]
            explicit = _PATH_ATTR.search(run)
            nested = [n for n, a, b in sorted(inline, key=lambda t: t[1]) if a < m.start() < b]
            here = base.joinpath(*nested) if nested else base
            if explicit:
                cands = [path.parent / explicit.group(1)]
            else:
                cands = [here / f"{name}.rs", here / name / "mod.rs"]
            child = next((c for c in cands if exists(c)), None)
            if child is None:
                findings.append(
                    f"{path}: `mod {name};` resolves to none of "
                    f"{[str(c) for c in cands]}, so its sites are ungraded"
                )
                continue
            stack.append((child, ctx + tuple(context_at(src.sites, m.start())), False))
    return out, findings


# ─── cargo's feature graph ───────────────────────────────────────────────────


@dataclass
class Package:
    name: str
    manifest: pathlib.Path
    features: dict[str, list[str]]
    deps: dict[str, str]
    roots: list[pathlib.Path] = field(default_factory=list)


def workspace_packages(crates: pathlib.Path) -> dict[str, Package]:
    proc = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=str(crates),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"`cargo metadata` failed: {proc.stderr.strip() or proc.returncode}")
    meta = json.loads(proc.stdout)
    out: dict[str, Package] = {}
    for p in meta["packages"]:
        deps = {(d.get("rename") or d["name"]): d["name"] for d in p.get("dependencies", [])}
        roots = [pathlib.Path(t["src_path"]) for t in p.get("targets", [])]
        out[p["name"]] = Package(
            p["name"], pathlib.Path(p["manifest_path"]), dict(p.get("features") or {}), deps, roots
        )
    return out


def reach(pkgs: dict[str, Package], pkg: str, feat: str) -> set[tuple[str, str]]:
    """Every (package, feature) that enabling `pkg/feat` turns on."""
    seen: set[tuple[str, str]] = set()
    stack = [(pkg, feat)]
    while stack:
        p, f = stack.pop()
        if (p, f) in seen or p not in pkgs:
            continue
        seen.add((p, f))
        for entry in pkgs[p].features.get(f, []):
            if entry.startswith("dep:"):
                continue
            if "/" in entry:
                dep, sub = entry.split("/", 1)
                target = pkgs[p].deps.get(dep.rstrip("?"))
                if target in pkgs:
                    stack.append((target, sub))
            elif entry in pkgs[p].features:
                stack.append((p, entry))
    return seen


def own_closure(pkgs: dict[str, Package], pkg: str, feats: Iterable[str]) -> frozenset[str]:
    out: set[str] = set()
    for f in feats:
        out |= {g for p, g in reach(pkgs, pkg, f) if p == pkg}
    return frozenset(out)


def bounded_features(
    pkgs: dict[str, Package], restricted: dict[str, frozenset[str]]
) -> dict[str, dict[str, frozenset[str]]]:
    """package -> {feature: the hosts every restricted runtime feature it turns on is served on}.

    `restricted` maps a wz-runtime-tokio feature to the hosts it is served on,
    for the features served on fewer than all of them.
    """
    out: dict[str, dict[str, frozenset[str]]] = {}
    for name, pkg in pkgs.items():
        for f in pkg.features:
            hit = {g for p, g in reach(pkgs, name, f) if p == RUNTIME and g in restricted}
            if not hit:
                continue
            bound = ALL_HOSTS
            for g in hit:
                bound &= restricted[g]
            out.setdefault(name, {})[f] = bound
    return out


# ─── arm 1 / arm 2: who serves what where ───────────────────────────────────


def _link_crate(kind: str) -> str:
    return "zenoh_link_" + axis.KINDS[kind][1].replace("-", "_")


def crate_hosts(crate_lib: str) -> tuple[list[tuple], frozenset[str]]:
    """Every `mod` a crate's lib.rs declares, and the hosts ALL of them compile on."""
    src = source(crate_lib, pathlib.Path("lib.rs"))
    preds: list[tuple] = []
    for m in _MOD_DECL.finditer(src.masked):
        preds += context_at(src.sites, m.start())
    return preds, hosts_of(preds, everything)


def upstream_link_served(
    registry: str, crate_lib: str, crate: str
) -> tuple[frozenset[str] | None, str]:
    """(hosts, how) for one upstream link crate, or (None, why) when unreadable."""
    reg = source(registry, REGISTRY)
    use = re.search(rf"\bpub use {re.escape(crate)} as \w+\s*;", reg.masked)
    if use is None:
        return None, f"no `pub use {crate} as ..` in the registry"
    preds = context_at(reg.sites, use.start())
    mods, _ = crate_hosts(crate_lib)
    preds += mods
    return hosts_of(preds, everything), " & ".join(render(p) for p in preds) or "ungated"


def wz_served(lib: str, module: str) -> tuple[frozenset[str] | None, str]:
    """The hosts wz compiles `pub mod <module>` on, every feature on."""
    src = source(lib, RUNTIME_LIB)
    decl = re.search(rf"\bpub mod {re.escape(module)}\s*;", src.masked)
    if decl is None:
        return None, f"no `pub mod {module};` in {RUNTIME_LIB}"
    preds = context_at(src.sites, decl.start())
    return hosts_of(preds, everything), " & ".join(render(p) for p in preds)


def _fmt(hosts: Iterable[str]) -> str:
    return "{" + ", ".join(h for h in HOSTS if h in hosts) + "}"


def matrix_findings(
    names: list[str],
    upstream: dict[str, frozenset[str]],
    wz: dict[str, frozenset[str]],
    gaps: dict[tuple[str, str], tuple[int, str]],
) -> list[str]:
    out: list[str] = []
    for name in names:
        up, mine = upstream[name], wz[name]
        for h in HOSTS:
            gap = gaps.get((name, h))
            if h in up and h not in mine and gap is None:
                out.append(
                    f"upstream serves {name} on {h} and wz does not, and no SERVE_GAPS "
                    f"row names the debt -- build it, or register the gap"
                )
            elif h in mine and h not in up:
                out.append(
                    f"wz serves {name} on {h}, where upstream's is inert -- wz must "
                    f"compile to what upstream does there, not to something of its own"
                )
            elif gap is not None and not (h in up and h not in mine):
                out.append(
                    f"SERVE_GAPS names ({name}, {h}) as item {gap[0]}, but wz and "
                    f"upstream now agree there -- the gap is closed: drop the row "
                    f"and close the item"
                )
    for name, _h in gaps:
        if name not in names:
            out.append(f"SERVE_GAPS names {name}, which is not a graded surface")
    return out


# ─── arm 3: every cfg site a restricted feature switches ────────────────────


def site_findings(
    files: list[tuple[SourceFile, tuple[tuple, ...]]],
    bounded: dict[str, frozenset[str]],
    rel: Callable[[pathlib.Path], str],
) -> tuple[list[str], int]:
    """(findings, sites graded) for one package's reached files.

    The rule is upstream's: on a host that does not serve the surface, naming
    the feature is INERT -- the build is the one it would be without it. So a
    site may not switch ON because of the feature there (it would compile
    against a module that is not there: the R2973 twelve errors), and it may not
    switch OFF either (the `not(feature)` fallback would vanish, leaving that
    host with neither arm).
    """
    out: list[str] = []
    graded = 0
    reported: set[tuple[str, int, str]] = set()
    for src, ctx in files:
        for site in src.sites:
            names = features_named(site.tree) & bounded.keys()
            if not names:
                continue
            full = ctx + tuple(context_at(src.sites, site.span[0])) + (site.tree,)
            for f in sorted(names):
                graded += 1
                on = hosts_of(full, everything)
                off = hosts_of(full, lambda g, f=f: g != f)
                key = (rel(src.path), site.line, f)
                if key in reported:
                    continue
                gained = (on - off) - bounded[f]
                lost = (off - on) - bounded[f]
                if gained:
                    reported.add(key)
                    out.append(
                        f"{key[0]}:{site.line}: `cfg({render(site.tree)})` switches ON "
                        f"with `{f}` on {_fmt(gained)}, where what it turns on is not "
                        f"served (served {_fmt(bounded[f])}) -- a build naming the "
                        f"feature there compiles this site against a module that is "
                        f"not there. Gate it on the host too."
                    )
                elif lost:
                    reported.add(key)
                    out.append(
                        f"{key[0]}:{site.line}: `cfg({render(site.tree)})` switches OFF "
                        f"with `{f}` on {_fmt(lost)}, where it is not served (served "
                        f"{_fmt(bounded[f])}) -- there the feature must be inert, and "
                        f"this fallback vanishes instead. Negate the feature AND its "
                        f"host together."
                    )
    return out, graded


# ─── arm 4: the execution legs ───────────────────────────────────────────────

_TEST_ATTR = re.compile(r"#\[\s*(?:tokio::)?test\b")
_FN = re.compile(r"\b(?:async\s+)?fn\s+([A-Za-z_]\w*)")


def head_features(src: SourceFile) -> tuple[frozenset[str] | None, str]:
    """The features a test target's inner `#![cfg]` needs, when it can be read.

    Only a conjunction of `feature = ..` atoms (plus host atoms) can be read as
    "enable these": an `any` has no single answer, and saying which branch the
    leg means is then the author's job, so it is refused rather than guessed.
    """
    trees = [s.tree for s in src.sites if s.inner and s.span[1] == len(src.masked)]
    feats: set[str] = set()

    def conj(tree: tuple) -> bool:
        if tree[0] == "all":
            return all(conj(a) for a in tree[1])
        if tree[0] == "kv" and tree[1] == "feature":
            feats.add(tree[2])
            return True
        return tree[0] == "id" or (tree[0] == "kv" and tree[1] != "feature")

    for t in trees:
        if not conj(t):
            return None, render(t)
    return frozenset(feats), " & ".join(render(t) for t in trees) or "ungated"


def runnable_tests(
    files: list[tuple[SourceFile, tuple[tuple, ...]]], host: str, enabled: frozenset[str]
) -> list[str]:
    out: list[str] = []
    for src, ctx in files:
        for m in _TEST_ATTR.finditer(src.masked):
            run_end = _skip_attrs(src.masked, m.start())
            run = src.masked[_attr_run_start(src.masked, m.start()) : run_end]
            if re.search(r"#\[\s*ignore\b", run):
                continue
            fn = _FN.match(src.masked, run_end)
            if fn is None:
                continue
            preds = ctx + tuple(context_at(src.sites, run_end))
            if hosts_of(preds, lambda f: f in enabled) & {host}:
                out.append(fn.group(1))
    return out


@dataclass
class Leg:
    host: str
    targets: list[str]
    features: frozenset[str]
    deferred: list[str]


def leg_findings(
    host: str,
    served: dict[str, frozenset[str]],
    target_files: Callable[[str], list[tuple[SourceFile, tuple[tuple, ...]]] | None],
    closure: Callable[[Iterable[str]], frozenset[str]],
    evidence: dict[str, tuple[str, ...]],
    exec_gaps: dict[tuple[str, str], tuple[int, str]],
) -> tuple[Leg, list[str]]:
    out: list[str] = []
    targets: list[str] = []
    wanted: set[str] = set()
    deferred: list[str] = []
    rows: list[tuple[str, str]] = []
    for kind in sorted(served):
        if host not in served[kind]:
            if (kind, host) in exec_gaps:
                out.append(
                    f"EXEC_GAPS names ({kind}, {host}), but wz does not serve {kind} "
                    f"there at all -- that is a SERVE question, not an execution one"
                )
            continue
        names = evidence.get(kind)
        if not names:
            out.append(f"wz serves {kind} on {host} and EVIDENCE names no target that runs it")
            continue
        for name in names:
            rows.append((kind, name))
    heads: dict[str, frozenset[str]] = {}
    for kind, name in rows:
        files = target_files(name)
        if files is None:
            out.append(f"EVIDENCE names `{name}` for {kind}, and there is no tests/{name}.rs")
            continue
        feats, how = head_features(files[0][0])
        if feats is None:
            out.append(
                f"tests/{name}.rs is gated `{how}`, which names no single feature set -- "
                f"the leg cannot say what to enable for it"
            )
            continue
        heads[name] = feats
    # An exec-gap link is still BUILT: the union build is the only place its
    # module compiles on this host at all.
    for kind, name in rows:
        if name in heads:
            wanted |= heads[name]
    enabled = closure(wanted)
    for kind, name in rows:
        if name not in heads:
            continue
        files = target_files(name)
        assert files is not None
        tests = runnable_tests(files, host, enabled)
        gap = exec_gaps.get((kind, host))
        if gap is not None:
            if tests:
                out.append(
                    f"EXEC_GAPS names ({kind}, {host}) as item {gap[0]}, but "
                    f"tests/{name}.rs now selects {len(tests)} test(s) there -- put "
                    f"it in the leg and close the item"
                )
            else:
                deferred.append(f"{kind} ({name}): item {gap[0]} -- {gap[1]}")
            continue
        if not tests:
            out.append(
                f"tests/{name}.rs is {kind}'s evidence on {host} and selects NO "
                f"runnable test there under the leg's features -- the leg would "
                f"pass it on an empty selection"
            )
            continue
        if name not in targets:
            targets.append(name)
    for kind, _h in exec_gaps:
        if kind not in served:
            out.append(f"EXEC_GAPS names {kind}, which `LinkKind` does not have")
    return Leg(host, targets, frozenset(wanted), deferred), out


_RUNNING = re.compile(r"^\s*Running (?:tests[\\/])?([A-Za-z0-9_-]+)\.rs\b")
_RESULT = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed")


def attribute_results(lines: Iterable[str]) -> dict[str, tuple[str, int]]:
    """target -> (verdict, passed), from cargo test's own output."""
    out: dict[str, tuple[str, int]] = {}
    current: str | None = None
    for line in lines:
        m = _RUNNING.match(line)
        if m:
            current = m.group(1)
            continue
        r = _RESULT.match(line)
        if r and current is not None:
            out[current] = (r.group(1), int(r.group(2)))
            current = None
    return out


def result_findings(leg: Leg, results: dict[str, tuple[str, int]], rc: int) -> list[str]:
    out: list[str] = []
    for t in leg.targets:
        got = results.get(t)
        if got is None:
            out.append(f"`{t}` reported no result -- it did not run")
        elif got[0] != "ok":
            out.append(f"`{t}` FAILED")
        elif got[1] < 1:
            out.append(f"`{t}` passed ZERO tests -- an empty selection is not evidence")
    if rc != 0 and not out:
        out.append(f"cargo exited {rc} with every target reporting green -- read the log")
    return out


def leg_command(leg: Leg) -> list[str]:
    cmd = ["cargo", "test", "-p", RUNTIME]
    if leg.features:
        cmd += ["--features", ",".join(sorted(leg.features))]
    for t in leg.targets:
        cmd += ["--test", t]
    return cmd


# ─── the real tree ───────────────────────────────────────────────────────────


@dataclass
class Tree:
    kinds: list[str]
    #: surface -> the wz-runtime-tokio feature that names it
    feature_of: dict[str, str]
    served: dict[str, frozenset[str]]
    pkgs: dict[str, Package]
    cache: dict[pathlib.Path, SourceFile]
    findings: list[str]

    @property
    def names(self) -> list[str]:
        return self.kinds + list(RUNTIME_FEATURES)


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def read_tree() -> Tree:
    findings: list[str] = []
    link_text = (ROOT / axis.WZ_LINK).read_text(encoding="utf-8")
    kinds = axis.wz_kinds(link_text)
    findings += axis.population_findings(kinds, axis.KINDS)
    unmapped = [k for k in kinds if k not in RUNTIME_LINKS]
    if unmapped:
        findings.append(f"`LinkKind` has {unmapped}, which RUNTIME_LINKS does not map")
    stale = [k for k in RUNTIME_LINKS if k not in kinds]
    if stale:
        findings.append(f"RUNTIME_LINKS maps {stale}, which `LinkKind` does not have")
    pkgs = workspace_packages(ROOT / "crates")
    if RUNTIME not in pkgs:
        raise RuntimeError(f"`{RUNTIME}` is not a workspace member")
    lib = (ROOT / RUNTIME_LIB).read_text(encoding="utf-8")
    feature_of: dict[str, str] = {}
    modules: dict[str, str] = {}
    for kind in kinds:
        if kind in RUNTIME_LINKS:
            feature_of[kind], modules[kind] = RUNTIME_LINKS[kind]
    for name, (feat, module, _crate) in RUNTIME_FEATURES.items():
        feature_of[name], modules[name] = feat, module
    served: dict[str, frozenset[str]] = {}
    for name, feat in feature_of.items():
        if feat not in pkgs[RUNTIME].features:
            findings.append(f"{name}'s feature `{feat}` is not a {RUNTIME} feature")
            continue
        hosts, how = wz_served(lib, modules[name])
        if hosts is None:
            findings.append(f"{name}: {how}")
            continue
        if not hosts:
            findings.append(f"{name}'s `pub mod {modules[name]}` is served on NO host ({how})")
        served[name] = hosts
    return Tree(kinds, feature_of, served, pkgs, {}, findings)


def upstream_matrix(
    root: pathlib.Path, tree: Tree
) -> tuple[dict[str, frozenset[str]], list[str]]:
    findings: list[str] = []
    upstream: dict[str, frozenset[str]] = {}
    registry = (root / REGISTRY).read_text(encoding="utf-8")
    for name in tree.names:
        if name in RUNTIME_LINKS:
            crate = _link_crate(name)
            lib = root / "io" / "zenoh-links" / crate.replace("zenoh_link_", "zenoh-link-") / "src" / "lib.rs"
        else:
            lib = root / RUNTIME_FEATURES[name][2] / "src" / "lib.rs"
        if not lib.is_file():
            findings.append(f"{name}: upstream has no {lib.relative_to(root)}")
            continue
        text = lib.read_text(encoding="utf-8")
        try:
            if name in RUNTIME_LINKS:
                hosts, how = upstream_link_served(registry, text, crate)
            else:
                preds, hosts = crate_hosts(text)
                how = " & ".join(render(p) for p in preds) or "ungated"
                if not preds:
                    hosts = None
                    how = f"{lib.relative_to(root)} declares no gated `mod`, so it says nothing about hosts"
        except UnknownCfg as e:
            findings.append(f"{name}: upstream gates it on `{e}`, which this gate cannot place")
            continue
        if hosts is None:
            findings.append(f"{name}: {how}")
            continue
        upstream[name] = hosts
    return upstream, findings


def check(require: bool, quiet: bool = False) -> tuple[Tree | None, dict[str, Leg], int]:
    try:
        tree = read_tree()
    except (RuntimeError, OSError, ValueError, UnknownCfg) as e:
        print(f"platform-surface-matrix: FAIL -- cannot read the tree: {e}")
        return None, {}, 1
    findings = list(tree.findings)

    # arm 1 + 2
    root = axis.upstream_root()
    upstream: dict[str, frozenset[str]] = {}
    if root is None:
        if require:
            findings.append(
                "the UPSTREAM arm needs a checkout of the pinned zenoh and found none, "
                "and `--require` was given -- a skip must not report green"
            )
        elif not quiet:
            print(
                "  platform-surface-matrix: the UPSTREAM arm (which hosts upstream "
                "serves each surface on) is SKIPPED -- no checkout of the pinned zenoh "
                "here. The wz arms graded only; do not read this as 'wz matches upstream'."
            )
    else:
        upstream, got = upstream_matrix(root, tree)
        findings += got
        if len(upstream) == len(tree.names) and len(tree.served) == len(tree.names):
            findings += matrix_findings(tree.names, upstream, tree.served, SERVE_GAPS)

    # arm 3
    restricted = {
        tree.feature_of[n]: h for n, h in tree.served.items() if h != ALL_HOSTS
    }
    bounded = bounded_features(tree.pkgs, restricted)
    graded = 0
    reached: set[pathlib.Path] = set()
    for name in sorted(bounded):
        for target_root in tree.pkgs[name].roots:
            if not target_root.is_file():
                continue
            try:
                files, missing = walk(
                    target_root, lambda p: load(p, tree.cache), pathlib.Path.is_file
                )
                got, n = site_findings(files, bounded[name], rel)
            except (UnknownCfg, ValueError) as e:
                findings.append(f"{rel(target_root)}: {e}")
                continue
            findings += [m for m in missing if m not in findings]
            findings += [g for g in got if g not in findings]
            graded += n
            reached |= {src.path for src, _ctx in files}

    # arm 4
    def closure(feats: Iterable[str]) -> frozenset[str]:
        return own_closure(tree.pkgs, RUNTIME, list(feats) + ["default"])

    def target_files(name: str) -> list[tuple[SourceFile, tuple[tuple, ...]]] | None:
        path = ROOT / RUNTIME_TESTS / f"{name}.rs"
        if not path.is_file():
            return None
        files, missing = walk(path, lambda p: load(p, tree.cache), pathlib.Path.is_file)
        findings.extend(m for m in missing if m not in findings)
        return files

    links = {k: h for k, h in tree.served.items() if k in RUNTIME_LINKS}
    legs: dict[str, Leg] = {}
    for host in LEG_HOSTS:
        try:
            leg, got = leg_findings(host, links, target_files, closure, EVIDENCE, EXEC_GAPS)
        except (UnknownCfg, ValueError) as e:
            findings.append(f"the {host} leg: {e}")
            continue
        findings += got
        legs[host] = leg

    if findings:
        print(f"platform-surface-matrix: FAIL -- {len(findings)} finding(s)")
        for f in findings:
            print(f"  {f}")
        return tree, legs, 1
    if not quiet:
        against = f"graded against {root}" if root is not None else "upstream arm SKIPPED"
        print(
            f"  platform-surface-matrix: {len(tree.names)} surface(s) x {len(HOSTS)} "
            f"hosts, {against}; {graded} cfg site(s) naming a host-restricted feature, "
            f"over {len(reached)} reached file(s) in {len(bounded)} crate(s), inert "
            f"where unserved"
        )
        for name in tree.names:
            up = _fmt(upstream[name]) if name in upstream else "?"
            print(f"    {name:15s} upstream {up:24s} wz {_fmt(tree.served[name])}")
        for (name, h), (item, _why) in sorted(SERVE_GAPS.items()):
            print(f"    SERVE GAP {name} on {h}: open-debt item {item}")
        for host, leg in legs.items():
            print(f"    leg {host}: {len(leg.targets)} target(s): {', '.join(leg.targets)}")
            for d in leg.deferred:
                print(f"    leg {host} DOES NOT EXECUTE {d}")
    return tree, legs, 0


def _this_host() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform in ("win32", "cygwin", "msys"):
        return "windows"
    return sys.platform


def run(host: str) -> int:
    if host not in LEG_HOSTS:
        print(f"platform-surface-matrix: no leg is declared for `{host}` (legs: {LEG_HOSTS})")
        return 2
    if _this_host() != host:
        print(
            f"platform-surface-matrix: the {host} leg must run ON {host}; this is "
            f"{_this_host()}. A leg run elsewhere proves nothing about the host."
        )
        return 2
    # The leg relays cargo's own output, and this tree's test messages carry
    # non-ASCII (an em dash is enough). A Windows runner's stdout is a pipe in
    # the ANSI code page, where writing one raises rather than printing, and it
    # would take the leg down after the tests had passed.
    sys.stdout.reconfigure(errors="replace")
    _tree, legs, rc = check(require=False)
    if rc != 0:
        return rc
    leg = legs[host]
    cmd = leg_command(leg)
    print(f"  platform-surface-matrix: {host} leg: {' '.join(cmd)}", flush=True)
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT / "crates"),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    lines: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stdout.write(line)
        lines.append(line.rstrip("\r\n"))
    rc = proc.wait()
    got = result_findings(leg, attribute_results(lines), rc)
    if got:
        print(f"platform-surface-matrix: {host} leg FAIL -- {len(got)} finding(s)")
        for f in got:
            print(f"  {f}")
        return 1
    print(f"  platform-surface-matrix: {host} leg: all {len(leg.targets)} target(s) passed")
    for d in leg.deferred:
        print(f"  platform-surface-matrix: {host} leg DID NOT EXECUTE {d}")
    return 0


# ─── selftest ────────────────────────────────────────────────────────────────


def _src(text: str, name: str = "x.rs") -> SourceFile:
    return source(text, pathlib.Path(name))


def _hosts(expr: str) -> frozenset[str]:
    tree, _ = parse_cfg(expr + ")", 0)
    return hosts_of([tree], lambda f: f == "on")


def selftest() -> int:
    failures: list[str] = []

    def expect(label: str, got: object, want: object) -> None:
        if got != want:
            failures.append(f"{label}: got {got!r}, want {want!r}")

    def refused(label: str, got: list[str], needle: str) -> None:
        if not any(needle in g for g in got):
            failures.append(f"{label}: expected a finding containing {needle!r}, got {got!r}")

    # predicates
    expect("unix", _hosts("unix"), UNIX_HOSTS)
    expect("all(feature, unix)", _hosts('all(feature = "on", unix)'), UNIX_HOSTS)
    expect("feature off", _hosts('all(feature = "off", unix)'), frozenset())
    expect("not macos", _hosts('not(target_os = "macos")'), frozenset({"linux", "windows"}))
    expect("family unix", _hosts('target_family = "unix"'), UNIX_HOSTS)
    expect("foreign os", _hosts('target_os = "android"'), frozenset())
    expect("any", _hosts('any(windows, target_os = "linux")'), frozenset({"linux", "windows"}))
    expect(
        "upstream's uring gate",
        _hosts('all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))'),
        frozenset({"linux"}),
    )
    expect("the runners' arch", _hosts('target_arch = "aarch64"'), frozenset({"macos"}))
    try:
        _hosts('target_endian = "little"')
        failures.append("an unknown cfg key was evaluated instead of refused")
    except UnknownCfg:
        pass

    # masking: a cfg in a comment, a string, or a raw string is not a site; a
    # comment INSIDE a predicate is not part of it; a macro body is a template
    s = _src(
        '// #[cfg(unix)]\n/* #[cfg(windows)] */\nconst A: &str = "#[cfg(unix)]";\n'
        "const B: &str = r#\"#[cfg(unix)]\"#;\nfn f<'a>(x: &'a u8) -> char { 'x' }\n"
        '#[cfg(feature = "on")]\nfn g() {}\n'
        '#[cfg(all(\n    unix, // a note\n    feature = "on"\n))]\nfn h() {}\n'
        "macro_rules! m { ($f:literal) => { #[cfg(feature = $f)] fn k() {} }; }\n"
    )
    expect("masked site count", len(s.sites), 2)
    expect("masked site line", s.sites[0].line, 6)
    expect("a commented predicate", render(s.sites[1].tree), 'all(unix, feature = "on")')

    # spans: an inner attribute reaches the file; a gated mod reaches its body
    s = _src('#![cfg(unix)]\nfn a() {}\n#[cfg(windows)]\nmod m {\n    fn b() {}\n}\nfn c() {}\n')
    pos_b = s.text.index("fn b")
    pos_c = s.text.index("fn c")
    expect("inner reach", [render(t) for t in context_at(s.sites, pos_c)], ["unix"])
    expect("mod reach", sorted(render(t) for t in context_at(s.sites, pos_b)), ["unix", "windows"])
    s = _src("match x {\n    #[cfg(unix)]\n    A => 1,\n    B => 2,\n}\n")
    expect("arm ends at comma", context_at(s.sites, s.text.index("B =>")), [])

    # arm 1: upstream's two link gates, read together, and a feature crate's
    registry = (
        '#[cfg(feature = "transport_tcp")]\npub use zenoh_link_tcp as tcp;\n'
        '#[cfg(all(feature = "transport_unixsock-stream", target_family = "unix"))]\n'
        "pub use zenoh_link_unixsock_stream as unixsock_stream;\n"
        '#[cfg(feature = "transport_unixpipe")]\npub use zenoh_link_unixpipe as unixpipe;\n'
        '#[cfg(all(feature = "transport_vsock", target_os = "linux"))]\n'
        "pub use zenoh_link_vsock as vsock;\n"
    )
    expect(
        "up tcp",
        upstream_link_served(registry, "mod unicast;\nmod utils;\n", "zenoh_link_tcp")[0],
        ALL_HOSTS,
    )
    expect(
        "up unixsock (registry gate)",
        upstream_link_served(registry, "mod unicast;\n", "zenoh_link_unixsock_stream")[0],
        UNIX_HOSTS,
    )
    expect(
        "up unixpipe (crate gate)",
        upstream_link_served(
            registry, "#[cfg(unix)]\nmod unix;\n#[cfg(unix)]\npub use unix::*;\n", "zenoh_link_unixpipe"
        )[0],
        UNIX_HOSTS,
    )
    expect(
        "up vsock",
        upstream_link_served(registry, '#[cfg(target_os = "linux")]\nmod unicast;\n', "zenoh_link_vsock")[0],
        frozenset({"linux"}),
    )
    expect("up absent", upstream_link_served(registry, "", "zenoh_link_ws")[0], None)
    uring = '#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]\nmod linux;\n'
    expect("up uring", crate_hosts(uring)[1], frozenset({"linux"}))

    # arm 2: wz's module cfg, and the matrix both ways
    lib = (
        '#[cfg(all(feature = "transport-link-unixsock", unix))]\npub mod unixsock_pipeline;\n'
        '#[cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]\n'
        "pub mod unixpipe_pipeline;\n"
        '#[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]\npub mod uring;\n'
    )
    wz_u = wz_served(lib, "unixsock_pipeline")[0]
    wz_p = wz_served(lib, "unixpipe_pipeline")[0]
    expect("wz unixsock", wz_u, UNIX_HOSTS)
    expect("wz unixpipe", wz_p, frozenset({"linux"}))
    expect("wz uring as R2973 found it", wz_served(lib, "uring")[0], ALL_HOSTS)
    names = ["UnixsockStream", "Unixpipe", "Uring"]
    up = {"UnixsockStream": UNIX_HOSTS, "Unixpipe": UNIX_HOSTS, "Uring": frozenset({"linux"})}
    fixed = {"UnixsockStream": wz_u, "Unixpipe": wz_p, "Uring": frozenset({"linux"})}
    got = matrix_findings(names, up, fixed, {})
    refused("deficit without a gap", got, "upstream serves Unixpipe on macos")
    gap = {("Unixpipe", "macos"): (851, "x")}
    expect("deficit with its gap", matrix_findings(names, up, fixed, gap), [])
    got = matrix_findings(names, up, {**fixed, "Uring": ALL_HOSTS}, gap)
    refused("the uring excess", got, "wz serves Uring on windows")
    got = matrix_findings(names, up, {**fixed, "Unixpipe": UNIX_HOSTS}, gap)
    refused("stale gap", got, "the gap is closed")

    # arm 3: the R2973 twelve-error shape, its repair, and what must stay quiet
    bound = {"transport-link-unixsock": UNIX_HOSTS}
    before = _src(
        '#[cfg(all(feature = "transport-link-unixsock", feature = "transport-unicast"))]\nfn a() {}\n'
    )
    got, n = site_findings([(before, ())], bound, str)
    refused("the unixsock site R2973 found", got, "switches ON with `transport-link-unixsock` on {windows}")
    expect("graded count", n, 1)
    after = _src(
        '#[cfg(all(feature = "transport-link-unixsock", feature = "transport-unicast", unix))]\nfn a() {}\n'
    )
    expect("the repaired site", site_findings([(after, ())], bound, str)[0], [])
    either = _src(
        '#[cfg(any(feature = "transport-link-tcp", all(feature = "transport-link-unixsock", unix)))]\nfn a() {}\n'
    )
    expect("a site the feature does not switch", site_findings([(either, ())], bound, str)[0], [])
    nested = _src('#[cfg(unix)]\nmod m {\n    #[cfg(feature = "transport-link-unixsock")]\n    fn a() {}\n}\n')
    expect("a nested site inherits its mod", site_findings([(nested, ())], bound, str)[0], [])
    bare = _src('#[cfg(feature = "transport-link-unixsock")]\nfn a() {}\n')
    unix_ctx = (parse_cfg("unix)", 0)[0],)
    expect("a file reached under unix", site_findings([(bare, unix_ctx)], bound, str)[0], [])
    refused("the same file reached bare", site_findings([(bare, ())], bound, str)[0], "{windows}")
    fallback = _src('#[cfg(not(feature = "transport-link-unixsock"))]\nfn a() {}\n')
    refused("a fallback that vanishes", site_findings([(fallback, ())], bound, str)[0], "switches OFF")
    kept = _src('#[cfg(not(all(feature = "transport-link-unixsock", unix)))]\nfn a() {}\n')
    expect("the fallback negated with its host", site_findings([(kept, ())], bound, str)[0], [])

    # arm 4: heads, runnable tests, gaps
    serial = _src(
        '#![cfg(all(feature = "transport-link-serial", unix))]\n'
        "#[tokio::test]\nasync fn a() {}\n#[test]\n#[ignore]\nfn b() {}\n",
        "serial_pty_e2e.rs",
    )
    expect("head features", head_features(serial)[0], frozenset({"transport-link-serial"}))
    feats = frozenset({"transport-link-serial"})
    expect("runnable on macos", runnable_tests([(serial, ())], "macos", feats), ["a"])
    expect("runnable on windows", runnable_tests([(serial, ())], "windows", feats), [])
    either_head = _src('#![cfg(any(feature = "a", feature = "b"))]\n#[test]\nfn t() {}\n')
    expect("an `any` head is refused", head_features(either_head)[0], None)
    files = {"serial_pty_e2e": [(serial, ())]}
    tf = files.get
    served = {"Serial": ALL_HOSTS}
    ev = {"Serial": ("serial_pty_e2e",)}
    leg, got = leg_findings("windows", served, tf, frozenset, ev, {})
    refused("an empty selection", got, "selects NO runnable test")
    xgap = {("Serial", "windows"): (852, "no COM pair")}
    leg, got = leg_findings("windows", served, tf, frozenset, ev, xgap)
    expect("the declared exec gap", got, [])
    expect("the gap is reported", len(leg.deferred), 1)
    expect("the gap's link is still built", sorted(leg.features), ["transport-link-serial"])
    leg, got = leg_findings("macos", served, tf, frozenset, ev, {})
    expect(
        "the macos leg",
        (leg.targets, sorted(leg.features), got),
        (["serial_pty_e2e"], ["transport-link-serial"], []),
    )
    leg, got = leg_findings("macos", served, tf, frozenset, ev, {("Serial", "macos"): (852, "x")})
    refused("a stale exec gap", got, "now selects 1 test(s)")
    leg, got = leg_findings("macos", {"Serial": ALL_HOSTS, "Ws": ALL_HOSTS}, tf, frozenset, ev, {})
    refused("a served link with no evidence", got, "EVIDENCE names no target")

    # the runner's attribution of cargo's output
    lines = [
        "     Running tests/tls_e2e.rs (target/debug/deps/tls_e2e-1)",
        "test result: ok. 8 passed; 0 failed; 0 ignored",
        "     Running tests\\ws_e2e.rs (target\\debug\\deps\\ws_e2e-2.exe)",
        "test result: ok. 0 passed; 0 failed; 5 ignored",
    ]
    res = attribute_results(lines)
    expect("attribution", res, {"tls_e2e": ("ok", 8), "ws_e2e": ("ok", 0)})
    leg = Leg("macos", ["tls_e2e", "ws_e2e", "quic_e2e"], frozenset(), [])
    got = result_findings(leg, res, 0)
    refused("zero passed", got, "`ws_e2e` passed ZERO")
    refused("never ran", got, "`quic_e2e` reported no result")
    one = Leg("macos", ["tls_e2e"], frozenset(), [])
    expect("all green", result_findings(one, res, 0), [])
    refused("rc without a red target", result_findings(one, res, 101), "exited 101")

    if failures:
        print(f"platform-surface-matrix selftest: FAIL -- {len(failures)}")
        for f in failures:
            print(f"  {f}")
        return 1
    print("  platform-surface-matrix selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="grade the real tree")
    mode.add_argument("--selftest", action="store_true", help="drive every verdict on fixtures")
    mode.add_argument("--legs", metavar="HOST", help="print HOST's leg command without running it")
    mode.add_argument("--run", metavar="HOST", help="run HOST's leg; must be run ON that host")
    ap.add_argument("--require", action="store_true", help="the upstream arm must run")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.check:
        return check(args.require)[2]
    host = (args.legs or args.run).lower()
    if args.run:
        return run(host)
    _tree, legs, rc = check(require=False, quiet=True)
    if rc != 0 or host not in legs:
        return rc or 2
    print(" ".join(leg_command(legs[host])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
