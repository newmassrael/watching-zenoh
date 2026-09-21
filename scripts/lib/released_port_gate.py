#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2781 (no register item) -- the RELEASED PORT gate.

The debt it answers for, open-debt item 810 (and 806 before it), lives in the
UNREGISTERED set, outside this repository, so there is no store id for the
provenance lint to resolve -- the position several gates here already record
for themselves.

## What it refuses, and why it exists

A test that needs an address nobody answers on has two ways to get one. It can
HOLD a socket that is bound and never listening -- the kernel refuses every
connect to it and gives the number to nobody else -- or it can bind a socket,
read its number and LET GO of it. The second is a number that belongs to
nobody, and the kernel hands it to the next `bind(:0)` it sees, including the
listener of a test running beside it in the same binary.

The class has been paid for twice, each time by a hosted red read from its
log body:

  * item 806 (run 35579977073): a node told to exit when its one peer was
    unreachable was given, as that peer, the number its own
    `tcp/127.0.0.1:0` listener then received. It connected to itself and
    never exited.
  * item 810 (run 35606210194): a replay test's quiet listener, which must
    never be dialled, accepted the retries another test in the same binary
    was aiming at a released number.

R2778 repaid 806 by building the one shared form, `refusing_port`, and
sweeping the tree for the other shape. The sweep was a search, not a gate,
and it missed the site that reded next -- in a crate outside the three the
sweep had framed the question around. A class that leaks twice gets a gate;
this is it.

## The population is DERIVED, and an empty one FAILs

Every `.local_addr()` in tracked `crates/**.rs`, read after comments are
stripped and literal bodies blanked (`rust_comments.strip_comments`), whose
value OUTLIVES the socket it was read from. Three shapes, each decided from
the code:

  T  the receiver is a TEMPORARY that a `bind` call produced in the same
     expression -- `TcpListener::bind(..).unwrap().local_addr()` -- so the
     socket dies at the end of the statement that read its number;
  D  the receiver is a local bound by a `bind` call and explicitly
     `drop`ped, and the value read from it (the `let` that carries it) is
     still used after the drop;
  S  the receiver is such a local and its SCOPE ends while the value leaves
     it -- as the block's tail value, through a `return`, or through a `let`
     whose name reaches either.

A member is a SITE, keyed `file::fn::receiver`. The gate prints the total and
refuses zero: a derivation that matches nothing reports on nothing.

## Classification, per site

Each member must be named in `CLASSIFIED` with one class from a CLOSED set
and a reason. Anything unnamed FAILs, and so does a row that names no
member -- a classification that outlived its site is a claim about nothing.

  listen-picker   the number is handed to something that will LISTEN on it
                  (item 553's class). A stolen number fails that bind loudly;
                  it cannot make a dial succeed that was meant to fail.
  not-a-port      the address is not a kernel-assigned IP port -- a unix
                  socket path, a pipe name, a vsock address the test chose.
  bind-probe      only the bind's success is the subject; the number is
                  never dialled.
  held-elsewhere  the HANDLE is dropped but the socket is not: another owner
                  the reason names keeps it open, so the number is not free.

There is deliberately no class for a DIAL TARGET that must refuse. That use
has exactly one correct shape -- hold the socket, `refusing_port` -- and a
released number used for it is the defect, so no row can make it green.

## What this does not see, stated

It reads text, not types. A value that escapes by being pushed into a
collection declared outside the socket's scope, or assigned to an outer
`mut` without `let`, is not followed; a receiver that is a field or a
parameter is not treated as released. Those shapes do not occur in this tree
today, and the selftest drives every shape the gate does claim.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rust_comments  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]

CLASSES = ("listen-picker", "not-a-port", "bind-probe", "held-elsewhere")

# `file::fn::socket` -> (class, reason). The socket is the local's name, `_`
# for a discarded tuple element, or `<temp>` for shape T. Measured at R2781:
# nine members, three of them dial targets that must refuse -- R2778's missed
# replay site, and a reconnect test whose peer went away and came back -- now
# holding their number through `refusing_port`, and so no longer members.
CLASSIFIED: dict[str, tuple[str, str]] = {
    "crates/wz-integration-tests/src/lib.rs::pick::listener": (
        "listen-picker",
        "PortGuard::pick reserves a number for a CHILD to `--listen` on (zenohd, "
        "a C example), under a process mutex and a cross-process file lock held "
        "until the child has bound it",
    ),
    "crates/wz-integration-tests/src/lib.rs::pick_pair::l1": (
        "listen-picker",
        "the first of two numbers PortGuard::pick_pair reserves for one child's "
        "two `--listen` endpoints, under the same two locks as `pick`",
    ),
    "crates/wz-integration-tests/src/lib.rs::pick_pair::l2": (
        "listen-picker",
        "the second of the pair, released beside the first and for the same "
        "child",
    ),
    "crates/wz-runtime-tokio-test-support/src/lib.rs::free_port::listener": (
        "listen-picker",
        "free_port returns a bare u16 for a C ABI that must bind the number "
        "itself; its own doc states the residue a u16 cannot close",
    ),
    "crates/wz-runtime-tokio-test-support/src/lib.rs::old_shape::<temp>": (
        "bind-probe",
        "the old bind-read-drop shape reproduced ON PURPOSE, to count how often "
        "this host re-hands a released number; the number is only compared, "
        "never dialled",
    ),
    "crates/wz-runtime-tokio/tests/static_peer_faces.rs::"
    "a_deploy_with_both_halves_holds_a_dialed_and_an_accepted_face::probe": (
        "listen-picker",
        "the number becomes the SUT's own `listen=` endpoint, which "
        "static_peer_sources binds; the dialled peer is a separate, held listener",
    ),
    "crates/wz-runtime-tokio/tests/udp_seam_e2e.rs::"
    "udp_stray_new_src_does_not_tear_down_a_one_shot_session::bound": (
        "held-elsewhere",
        "dropping the listener handle is the subject; the UDP socket lives on in "
        "the demux pump the accepted face still holds by Arc, which is where "
        "the stray datagram to this number must arrive",
    ),
}

LOCAL_ADDR = re.compile(r"\.\s*local_addr\s*\(\s*\)")
BIND_CALL = re.compile(r"(?:\bbind\w*|::bind)\s*(?:::<[^>]*>)?\s*\(")
FN_DECL = re.compile(r"\bfn\s+([A-Za-z_]\w*)")
IDENT = re.compile(r"[A-Za-z_]\w*\Z")


def braces(text: str) -> dict[int, int]:
    """`{open index: matching close index}` over literal-blanked text."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for i, ch in enumerate(text):
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            pairs[stack.pop()] = i
    return pairs


def fn_bodies(text: str, pairs: dict[int, int]) -> list[tuple[str, int, int]]:
    """`(name, open, close)` for every fn with a body."""
    out = []
    for m in FN_DECL.finditer(text):
        j = m.end()
        # The body is the first `{` after the signature; a `;` first means a
        # declaration with no body (a trait method, an extern fn).
        while j < len(text) and text[j] not in "{;":
            j += 1
        if j < len(text) and text[j] == "{" and j in pairs:
            out.append((m.group(1), j, pairs[j]))
    return out


def innermost(spans: list[tuple[int, int]], pos: int) -> tuple[int, int] | None:
    best = None
    for o, c in spans:
        if o < pos < c and (best is None or o > best[0]):
            best = (o, c)
    return best


def receiver(text: str, dot: int) -> str:
    """The expression `.local_addr()` is called on, read backwards from `dot`:
    identifiers, paths, `.await`, `?`, and balanced `(...)`/`[...]` groups."""
    i = dot
    depth = 0
    while i > 0:
        ch = text[i - 1]
        if depth:
            if ch in ")]":
                depth += 1
            elif ch in "([":
                depth -= 1
            i -= 1
            continue
        if ch in ")]":
            depth += 1
            i -= 1
            continue
        if ch.isalnum() or ch in "_.?:" or ch.isspace():
            i -= 1
            continue
        if ch == "!" or ch == "&":
            i -= 1
            continue
        break
    return text[i:dot].strip()


def top_level_semis(text: str, lo: int, hi: int) -> list[int]:
    """Positions of `;` directly inside the block `(lo, hi)`, not nested."""
    out = []
    depth = 0
    for i in range(lo + 1, hi):
        ch = text[i]
        if ch in "{([":
            depth += 1
        elif ch in "})]":
            depth -= 1
        elif ch == ";" and depth == 0:
            out.append(i)
    return out


def statement_start(text: str, block: tuple[int, int], pos: int) -> int:
    """Start of the top-level statement of `block` that contains `pos`."""
    semis = [s for s in top_level_semis(text, *block) if s < pos]
    return (semis[-1] + 1) if semis else block[0] + 1


def carrier(text: str, block: tuple[int, int], pos: int) -> str | None:
    """The name a `let` binds the statement containing `pos` to, if it is a
    `let NAME = ...;` statement of `block` or of a block inside it."""
    start = statement_start(text, block, pos)
    m = re.match(r"\s*let\s+(?:mut\s+)?([A-Za-z_]\w*)\b", text[start:pos])
    return m.group(1) if m else None


def mentions(lit: str, name: str) -> bool:
    """Whether `name` is used in `lit`, format-string captures included:
    `format!("tcp/{addr}")` uses `addr` from inside a literal, so this reads
    the literal-KEEPING text, never the blanked one."""
    return bool(re.search(rf"\b{re.escape(name)}\b", lit))


def unit_fn_body(text: str, block: tuple[int, int], fns) -> bool:
    """Whether `block` is the body of a fn that returns nothing: its tail is a
    statement without a semicolon (`assert_eq!(..)`), not a value leaving."""
    for _, o, c in fns:
        if (o, c) == block:
            head = text[max(0, text.rfind("fn", 0, o)) : o]
            return "->" not in head
    return False


def held(text: str, lit: str, block: tuple[int, int], pos: int, sock: str) -> bool:
    """Whether the socket named `sock` is still owned by something after `pos`:
    used BY VALUE (moved into a call, a struct, a task) or captured by a `move`
    closure or `async move` block. A `&sock` borrow and a `sock.method()` call
    leave it where it is, so they do not count.

    A by-value use counts only at the TOP LEVEL of the socket's own block.
    Inside a branch it holds the socket on that path alone, and the path that
    does not take it is the release: `free_port` keeps a rejected candidate in
    an `if` and returns the number of the one it lets go. Reading that as held
    was measured to drop the helper out of the population, so a branch-local
    move is not evidence -- the conservative direction, since a site wrongly
    kept costs one classification and a site wrongly dropped costs a red."""
    for m in re.finditer(rf"\b{re.escape(sock)}\b", lit[pos : block[1]]):
        at = pos + m.start()
        inner = text[block[0] + 1 : at]
        if inner.count("{") != inner.count("}"):
            continue
        after = text[at + len(sock) :].lstrip()
        before = text[:at].rstrip()
        if after.startswith("."):
            continue
        if before.endswith("&") or re.search(r"&\s*mut$", before):
            continue
        if re.search(r"\bdrop\s*\(\s*$", before):
            continue
        # A later `let sock = ...` is a NEW binding shadowing this one, not a
        # use of it.
        if re.search(r"\blet\s+(?:mut\s+)?$", before):
            continue
        return True
    for m in re.finditer(r"\bmove\b", text[pos : block[1]]):
        at = pos + m.end()
        opened = text.find("{", at)
        if opened < 0 or opened >= block[1]:
            continue
        close = braces_close(text, opened)
        if close and re.search(rf"\b{re.escape(sock)}\b", lit[opened:close]):
            return True
    return False


def braces_close(text: str, opened: int) -> int | None:
    depth = 0
    for i in range(opened, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def escapes(
    text: str, lit: str, block: tuple[int, int], pos: int, name: str | None, fns=()
) -> bool:
    """Whether the value at `pos` (or carried by `name`) leaves `block`: as its
    tail value, or through a `return` inside it. `text` is the literal-blanked
    view structure is read from; `lit` the same span with literals kept, which
    is where names are looked for. The body of a fn returning nothing has no
    tail VALUE, so a name in its last statement leaves nothing."""
    if unit_fn_body(text, block, fns):
        return False
    semis = top_level_semis(text, *block)
    tail_start = (semis[-1] + 1) if semis else block[0] + 1
    if pos >= tail_start and text[tail_start : block[1]].strip():
        return True
    if name and mentions(lit[tail_start : block[1]], name):
        return True
    for m in re.finditer(r"\breturn\b", text[pos : block[1]]):
        at = pos + m.end()
        end = next((j for j in range(at, block[1]) if text[j] in ";}"), block[1])
        if name and mentions(lit[at:end], name):
            return True
    return False


def moved_out(text: str, lit: str, block: tuple[int, int], recv: str) -> bool:
    """Whether the socket itself leaves the block beside its number -- a bare
    use of its name (not a method call on it) in the block's tail."""
    semis = top_level_semis(text, *block)
    tail_start = (semis[-1] + 1) if semis else block[0] + 1
    return bool(re.search(rf"\b{re.escape(recv)}\b(?!\s*\.)", lit[tail_start : block[1]]))


def sites(rel: str, raw: str) -> list[tuple[str, int, str]]:
    """`(key, line, shape)` for every member in one file."""
    text = rust_comments.strip_comments(raw, blank_literals=True)
    # The same span with literals KEPT. Blanking preserves every offset, so an
    # index into one is the same place in the other.
    lit = rust_comments.strip_comments(raw)
    assert len(lit) == len(text), "blanking must preserve offsets"
    pairs = braces(text)
    fns = fn_bodies(text, pairs)
    spans = list(pairs.items())
    out = []
    for m in LOCAL_ADDR.finditer(text):
        dot = m.start()
        line = text.count("\n", 0, dot) + 1
        owner = innermost([(o, c) for _, o, c in fns], dot)
        fn = next((n for n, o, c in fns if (o, c) == owner), "<top>")
        recv = receiver(text, dot)
        if BIND_CALL.search(recv):
            out.append((f"{rel}::{fn}::<temp>", line, "T"))
            continue
        if not IDENT.match(recv) or owner is None:
            continue
        # The nearest `let RECV = ...` before the site, inside the same fn.
        lets = list(
            re.finditer(rf"\blet\s+(?:mut\s+)?{re.escape(recv)}\b[^=;]*=", text[owner[0] : dot])
        )
        if not lets:
            continue
        let_at = owner[0] + lets[-1].start()
        scope = innermost(spans, let_at)
        if scope is None:
            continue
        init_end = next((s for s in top_level_semis(text, *scope) if s > let_at), scope[1])
        if not BIND_CALL.search(text[let_at:init_end]):
            continue
        name = carrier(text, scope, dot)
        # D: an explicit drop of the socket, with the value still used after.
        dropped = re.search(rf"\bdrop\s*\(\s*{re.escape(recv)}\s*\)", text[dot : owner[1]])
        if dropped:
            after = dot + dropped.end()
            if name is None or mentions(lit[after : owner[1]], name):
                out.append((f"{rel}::{fn}::{recv}", line, "D"))
                continue
        # S: the socket's scope ends while the value leaves it, and nothing
        # took the socket with it.
        if (
            escapes(text, lit, scope, dot, name, fns)
            and not moved_out(text, lit, scope, recv)
            and not held(text, lit, scope, dot + 1, recv)
        ):
            out.append((f"{rel}::{fn}::{recv}", line, "S"))
    out.extend(pair_sites(rel, text, lit, pairs, fns, spans))
    return out


LET_TUPLE = re.compile(r"\blet\s+\(([^()=;]*)\)\s*(?::[^=;]*)?=")


def pair_sites(rel, text, lit, pairs, fns, spans) -> list[tuple[str, int, str]]:
    """The same three releases when the address never passes through a
    `.local_addr()` in this file: a helper hands back `(socket, address)` and
    the caller destructures it. The site R2778's own notes called a listen
    picker -- `let (probe, addr) = bind_loopback().await; drop(probe);` -- is
    this shape, and a gate anchored on `.local_addr()` alone cannot see it.

    The pattern does not say which element is the socket, so each element is
    tried as one: D when it is `drop`ped and another element is used after;
    S when it is never used by value again and another element leaves its
    scope; and a `_` element beside a named one is a socket discarded at the
    end of the statement (T), since a wildcard binds nothing and holds nothing.
    """
    out = []
    for m in LET_TUPLE.finditer(text):
        let_at = m.start()
        owner = innermost([(o, c) for _, o, c in fns], let_at)
        if owner is None:
            continue
        fn = next(n for n, o, c in fns if (o, c) == owner)
        scope = innermost(spans, let_at)
        if scope is None:
            continue
        init_end = next((s for s in top_level_semis(text, *scope) if s > let_at), scope[1])
        if not BIND_CALL.search(text[m.end() : init_end]):
            continue
        names = []
        for part in m.group(1).split(","):
            part = re.sub(r"^\s*(?:ref\s+)?(?:mut\s+)?", "", part).strip()
            if part:
                names.append(part)
        if not names or not all(p == "_" or IDENT.match(p) for p in names):
            continue
        line = text.count("\n", 0, let_at) + 1
        named = [p for p in names if p != "_"]
        if "_" in names and named:
            out.append((f"{rel}::{fn}::_", line, "T"))
            continue
        for sock in named:
            others = [p for p in named if p != sock]
            if not others:
                continue
            dropped = re.search(rf"\bdrop\s*\(\s*{re.escape(sock)}\s*\)", text[init_end : owner[1]])
            if dropped:
                after = init_end + dropped.end()
                if any(mentions(lit[after : owner[1]], o) for o in others):
                    out.append((f"{rel}::{fn}::{sock}", line, "D"))
                    break
                continue
            if not held(text, lit, scope, init_end, sock) and any(
                escapes(text, lit, scope, init_end, o, fns) for o in others
            ):
                out.append((f"{rel}::{fn}::{sock}", line, "S"))
                break
    return out


def population() -> list[tuple[str, int, str]]:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "crates"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    out = []
    for rel in sorted(p for p in listed.split("\0") if p.endswith(".rs")):
        try:
            raw = (ROOT / rel).read_text(errors="replace")
        except OSError:
            continue
        if "local_addr" not in raw:
            continue
        out.extend(sites(rel, raw))
    return out


def judge(
    members: list[tuple[str, int, str]],
    classified: dict[str, tuple[str, str]] | None = None,
) -> list[str]:
    classified = CLASSIFIED if classified is None else classified
    findings = []
    if not members:
        findings.append(
            "the derivation found no site at all, which reads exactly like a clean "
            "tree and is not evidence of one"
        )
    keys = {k for k, _, _ in members}
    for key, line, shape in members:
        if key not in classified:
            findings.append(
                f"{key.split('::')[0]}:{line}: a released port (shape {shape}) in "
                f"`{key.split('::')[1]}`, unclassified. If the number is dialled and "
                "must refuse, HOLD it: `wz_runtime_tokio_test_support::refusing_port`. "
                f"Otherwise classify it ({', '.join(CLASSES)}) with its reason."
            )
    for key, (cls, reason) in classified.items():
        if cls not in CLASSES:
            findings.append(f"{key}: class `{cls}` is not one of {CLASSES}")
        if not reason.strip():
            findings.append(f"{key}: classified with no reason")
        if key not in keys:
            findings.append(f"{key}: classified, but no such released-port site exists")
    return findings


def run() -> int:
    members = population()
    shapes = {s: sum(1 for _, _, x in members if x == s) for s in "TDS"}
    print(
        f"released-port gate: {len(members)} site(s) where a socket's number "
        f"outlives the socket (T {shapes['T']}, D {shapes['D']}, S {shapes['S']}); "
        f"{len(CLASSIFIED)} classified"
    )
    findings = judge(members)
    for f in findings:
        print(f"  FAIL {f}")
    if findings:
        print(f"released-port gate: FAIL -- {len(findings)} finding(s)")
        return 1
    print("released-port gate: ok")
    return 0


def selftest() -> int:
    bad = []
    fixtures = {
        "T": (
            "fn free() -> u16 {\n"
            '    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()\n'
            "}\n",
            1,
        ),
        "D": (
            "async fn t() {\n"
            '    let doomed = TcpListener::bind("127.0.0.1:0").await.unwrap();\n'
            "    let addr = doomed.local_addr().unwrap();\n"
            "    drop(doomed);\n"
            '    dial(format!("tcp/{addr}"));\n'
            "}\n",
            1,
        ),
        "S-block": (
            "fn t() {\n"
            "    let dead = {\n"
            '        let l = TcpListener::bind("127.0.0.1:0").unwrap();\n'
            "        l.local_addr().unwrap()\n"
            "    };\n"
            "    dial(dead);\n"
            "}\n",
            1,
        ),
        "S-return": (
            "fn pick() -> u16 {\n"
            '    let l = TcpListener::bind("127.0.0.1:0").unwrap();\n'
            "    let port = l.local_addr().unwrap().port();\n"
            "    if port == 0 { panic!() }\n"
            "    return port;\n"
            "}\n",
            1,
        ),
        # CONTROLS: a HELD socket, and a socket returned beside its number,
        # are not released. Without these every arm above is satisfied by a
        # gate that reports every `local_addr` it sees.
        "held": (
            "async fn t() {\n"
            '    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();\n'
            "    let addr = listener.local_addr().unwrap();\n"
            "    let (s, _) = listener.accept().await.unwrap();\n"
            "    drop(s);\n"
            "}\n",
            0,
        ),
        "moved-out": (
            "fn pair() -> (TcpListener, SocketAddr) {\n"
            '    let l = TcpListener::bind("127.0.0.1:0").unwrap();\n'
            "    let a = l.local_addr().unwrap();\n"
            "    (l, a)\n"
            "}\n",
            0,
        ),
        "dropped-after-use": (
            "async fn t() {\n"
            '    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();\n'
            "    let addr = listener.local_addr().unwrap();\n"
            "    serve(&listener, addr).await;\n"
            "    drop(listener);\n"
            "}\n",
            0,
        ),
        "not-bound": (
            "async fn t(stream: TcpStream) {\n"
            "    let s = connect().await;\n"
            "    let a = s.local_addr().unwrap();\n"
            "    drop(s);\n"
            "    log(a);\n"
            "}\n",
            0,
        ),
        "pair D": (
            "async fn t() {\n"
            "    let sut = {\n"
            "        let (probe, addr) = bind_loopback().await;\n"
            "        drop(probe);\n"
            "        addr\n"
            "    };\n"
            '    listen(format!("tcp/{sut}"));\n'
            "}\n",
            1,
        ),
        "pair S": (
            "fn dead() -> SocketAddr {\n"
            "    let (l, a) = bind_loopback();\n"
            "    a\n"
            "}\n",
            1,
        ),
        "pair wildcard": (
            "async fn t() {\n"
            "    let (_, addr) = bind_loopback().await;\n"
            "    dial(addr);\n"
            "}\n",
            1,
        ),
        # CONTROLS for "held elsewhere": a socket a `move` closure captures,
        # or one moved into an `async move` task, outlives its scope there;
        # and a unit fn's last statement returns no value.
        "move closure": (
            "fn proxy() -> u16 {\n"
            '    let listener = TcpListener::bind("127.0.0.1:0").unwrap();\n'
            "    let port = listener.local_addr().unwrap().port();\n"
            "    std::thread::spawn(move || { let _ = listener.accept(); });\n"
            "    port\n"
            "}\n",
            0,
        ),
        "async move task": (
            "async fn fixture() -> SocketAddr {\n"
            '    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();\n'
            "    let addr = listener.local_addr().unwrap();\n"
            "    tokio::spawn(async move { serve_on(listener).await });\n"
            "    addr\n"
            "}\n",
            0,
        ),
        # The branch case, as `free_port` has it: held on one path, released
        # and returned on the other. A MEMBER.
        "held on one branch only": (
            "fn free_port() -> u16 {\n"
            "    let mut rejected = Vec::new();\n"
            "    loop {\n"
            '        let listener = TcpListener::bind("127.0.0.1:0").unwrap();\n'
            "        let port = listener.local_addr().unwrap().port();\n"
            "        if seen(port) {\n"
            "            rejected.push(listener);\n"
            "            continue;\n"
            "        }\n"
            "        return port;\n"
            "    }\n"
            "}\n",
            1,
        ),
        "unit fn tail": (
            "async fn t() {\n"
            '    let bound = bind_endpoint("udp/127.0.0.1:0").await.unwrap();\n'
            "    let addr = bound.local_addr().unwrap();\n"
            "    run(&bound).await;\n"
            "    assert_eq!(seen(), addr)\n"
            "}\n",
            0,
        ),
        # CONTROL for the pair shapes: a socket that is USED by value (moved
        # into a task, passed by reference) is held there, not released.
        "pair held": (
            "async fn t() {\n"
            "    let (listener, addr) = bind_loopback().await;\n"
            "    tokio::spawn(serve(listener));\n"
            "    dial(addr);\n"
            "}\n",
            0,
        ),
        "brace in a literal": (
            "fn t() {\n"
            '    let l = TcpListener::bind("127.0.0.1:0").unwrap();\n'
            '    let a = format!("{}}}", l.local_addr().unwrap());\n'
            "    drop(l);\n"
            "    dial(a);\n"
            "}\n",
            1,
        ),
    }
    for name, (src, want) in fixtures.items():
        got = len(sites("x.rs", src))
        if got != want:
            bad.append(f"{name}: {got} site(s), want {want}")

    # The VERDICT, driven on its own: each rule must turn a finding on, and the
    # classified member must turn it off, or the rules are decoration.
    member = [("x.rs::t::doomed", 3, "D")]
    row = {"x.rs::t::doomed": ("listen-picker", "a child listens on it")}
    verdicts = {
        "unclassified member": (judge(member, {}), 1),
        "classified member": (judge(member, row), 0),
        "row naming no member": (judge(member, {**row, "x.rs::gone::l": row["x.rs::t::doomed"]}), 1),
        "class outside the set": (judge(member, {"x.rs::t::doomed": ("dial-target", "r")}), 1),
        "row with no reason": (judge(member, {"x.rs::t::doomed": ("bind-probe", " ")}), 1),
        "empty population": (judge([], {}), 1),
    }
    for name, (found, want) in verdicts.items():
        if len(found) != want:
            bad.append(f"verdict, {name}: {len(found)} finding(s), want {want}")
    for b in bad:
        print(f"  released-port selftest FAIL -- {b}")
    if bad:
        return 1
    print(f"released-port gate: selftest ok ({len(fixtures)} fixture(s), controls included)")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    if sys.argv[1:]:
        print(f"released-port gate: unknown argument(s) {sys.argv[1:]}", file=sys.stderr)
        return 2
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
