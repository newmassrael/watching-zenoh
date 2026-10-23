#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3439 (no register item) -- a drop-in header carries upstream's symbols only; wz's own are wz_ext_.

Decision C10 of docs/build-configuration.md: a drop-in header declares only what its upstream
header declares, and a door wz has and upstream does not is `wz_ext_*`, declared in `wz_ext.h`.
Then "drop-in" is a claim a compiler can check: a program that includes the drop-in header and
not `wz_ext.h` is portable to the upstream library, and one that needs `wz_ext.h` says so.

    (no argument)   check
    --selftest      every refusal on a fixture

## What is compared

DROP-IN   the functions `crates/wz-capi-pico/include/wz_capi_pico.h` declares: wz's own
          spelling of zenoh-pico's header, which a C program may compile against instead of
          upstream's.
UPSTREAM  the functions zenoh-pico's own header declares at the pinned source
          (`vendor/zenoh-pico/include/zenoh-pico.h`), after the preprocessor: pico generates
          most of its owned-type functions with macros, so a text search of its headers misses
          them (measured: five of the drop-in's names). Its `config.h` is rendered here from the
          pinned `config.h.in` with the defaults its `CMakeLists.txt` sets, so no build tree is
          needed, and the header is read under three configurations whose union is the set:
          upstream's defaults, every switch on, and every switch on but single-threaded (the
          thread switch changes which functions exist rather than adding some).
EXT       the functions `crates/wz-capi-core/include/wz_ext.h` declares, every one `wz_ext_*`.

A switch whose header needs a library the pinned source does not carry is left off in the
all-on configuration, and is listed with the reason. The list is held too: a switch on it that
now preprocesses is a finding, since leaving it off would hide its functions from the set.

zenoh-c has no drop-in header of wz's: a program includes upstream's `zenoh.h`, and
`crates/wz-capi-c/include/wz_capi_c.h` declares only wz's own doors (`capi_c_wz_door_header.py`).
Those doors keep the `wz_capi_c_` prefix they were published with; moving them to `wz_ext_`
is a change a consumer must be told of first.

An empty set on either side fails: a reader that stopped matching reads as a header with
nothing outside upstream.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
PICO = ROOT / "vendor" / "zenoh-pico"
DROP_IN = ROOT / "crates" / "wz-capi-pico" / "include" / "wz_capi_pico.h"
EXT = ROOT / "crates" / "wz-capi-core" / "include" / "wz_ext.h"
EXT_PREFIX = "wz_ext_"
# The switches whose headers need what the pinned source does not carry.
NEEDS_A_LIBRARY = {
    "Z_FEATURE_LINK_TLS": "link/transport/tls_stream.h includes Mbed TLS (mbedtls/ssl.h)",
}
CMAKE_FALSE = {"", "0", "OFF", "NO", "FALSE", "N", "IGNORE", "NOTFOUND"}
KEYWORDS = {"return", "sizeof", "if", "while", "for", "switch", "else", "do", "case",
            "_Static_assert", "static_assert", "defined", "__attribute__", "__typeof__", "typeof"}
DECL_RE = re.compile(r"(?:\b([A-Za-z_]\w*)\s*\**|\*)\s*\b([A-Za-z_]\w*)\s*\(")


def cmake_defaults(cmakelists: str) -> dict[str, str]:
    """`set(NAME value CACHE ...)`, the defaults a configure starts from."""
    found = re.findall(r'^\s*set\((\w+)\s+("[^"]*"|[^\s)]+)\s+CACHE\b', cmakelists, re.M)
    return {name: value.strip('"') for name, value in found}


def render_config(template: str, values: dict[str, str]) -> str:
    """`config.h.in` as CMake's `configure_file` renders it for `values`."""
    out = []
    for line in template.splitlines():
        directive = re.match(r"#cmakedefine\s+(\w+)(.*)$", line)
        if directive:
            name, rest = directive.groups()
            if values.get(name, "").upper() in CMAKE_FALSE:
                out.append(f"/* #undef {name} */")
            else:
                out.append(f"#define {name}" + re.sub(r"@(\w+)@", lambda m: values.get(m.group(1), ""), rest))
            continue
        out.append(re.sub(r"@(\w+)@", lambda m: values.get(m.group(1), ""), line))
    return "\n".join(out) + "\n"


def declared_functions(preprocessed: str) -> set[str]:
    """The names a C text declares or defines as functions: a name after a type (or a `*`) and
    before `(`. A call after `=`, `(`, `,` or `return` is not one."""
    names = set()
    for match in DECL_RE.finditer(preprocessed):
        before, name = match.group(1), match.group(2)
        if name in KEYWORDS or before in KEYWORDS:
            continue
        names.add(name)
    return names


def preprocess(header: pathlib.Path, config: str | None, include: list[pathlib.Path]) -> str:
    """`cc -E -P` of `header` as a Linux build sees it; `config` is written as
    `zenoh-pico/config.h` ahead of the include path. Raises `RuntimeError` with cc's message."""
    with tempfile.TemporaryDirectory() as tmp:
        dirs = []
        if config is not None:
            (pathlib.Path(tmp) / "zenoh-pico").mkdir()
            (pathlib.Path(tmp) / "zenoh-pico" / "config.h").write_text(config, encoding="utf-8")
            dirs.append(pathlib.Path(tmp))
        cmd = ["cc", "-E", "-P", "-DZENOH_LINUX", *[f"-I{d}" for d in dirs + include], str(header)]
        done = subprocess.run(cmd, capture_output=True, text=True)
    if done.returncode != 0:
        last = [line for line in done.stderr.splitlines() if "error" in line]
        raise RuntimeError(last[0] if last else done.stderr.strip()[:200])
    return done.stdout


def configurations(defaults: dict[str, str]) -> dict[str, dict[str, str]]:
    switches = [name for name in defaults if name.startswith("Z_FEATURE_")]
    all_on = dict(defaults, **{name: "1" for name in switches if name not in NEEDS_A_LIBRARY})
    return {
        "upstream's defaults": dict(defaults),
        "every switch on": all_on,
        "every switch on, single-threaded": dict(all_on, Z_FEATURE_MULTI_THREAD="0"),
    }


def upstream_functions(pico: pathlib.Path) -> tuple[set[str], list[str]]:
    """The union of the functions zenoh-pico's header declares, and findings."""
    defaults = cmake_defaults((pico / "CMakeLists.txt").read_text(encoding="utf-8"))
    template = (pico / "include" / "zenoh-pico" / "config.h.in").read_text(encoding="utf-8")
    header = pico / "include" / "zenoh-pico.h"
    include = [pico / "include"]
    out: set[str] = set()
    findings = []
    for label, values in configurations(defaults).items():
        try:
            out |= declared_functions(preprocess(header, render_config(template, values), include))
        except RuntimeError as exc:
            findings.append(f"zenoh-pico's header does not preprocess with {label}: {exc}")
    for switch, reason in NEEDS_A_LIBRARY.items():
        if switch not in defaults:
            findings.append(f"{switch} is listed as needing a library and the pinned CMakeLists sets no such switch")
            continue
        try:
            preprocess(header, render_config(template, dict(defaults, **{switch: "1"})), include)
            findings.append(f"{switch} preprocesses now; it is listed as needing a library "
                            f"({reason}), which leaves its functions out of the set")
        except RuntimeError:
            pass
    return out, findings


def check(pico: pathlib.Path, drop_in: pathlib.Path, ext: pathlib.Path) -> list[str]:
    if shutil.which("cc") is None:
        return ["no `cc` on PATH: the headers cannot be preprocessed, and nothing here was read"]
    upstream, findings = upstream_functions(pico)
    if not upstream:
        findings.append("zenoh-pico's header declares no function here: the reader stopped matching it")
    try:
        ours = declared_functions(preprocess(drop_in, None, []))
    except RuntimeError as exc:
        return findings + [f"{drop_in.name} does not preprocess: {exc}"]
    if not ours:
        findings.append(f"{drop_in.name} declares no function here: the reader stopped matching it")
    for name in sorted(ours - upstream):
        findings.append(f"{drop_in.name} declares {name}, which zenoh-pico's header does not"
                        + (" (a wz door belongs in wz_ext.h)" if name.startswith(EXT_PREFIX) else ""))
    if not ext.is_file():
        findings.append(f"{ext.relative_to(ROOT) if ext.is_relative_to(ROOT) else ext} is missing")
    else:
        try:
            for name in sorted(declared_functions(preprocess(ext, None, []))):
                if not name.startswith(EXT_PREFIX):
                    findings.append(f"{ext.name} declares {name}, which is not {EXT_PREFIX}*")
        except RuntimeError as exc:
            findings.append(f"{ext.name} does not preprocess: {exc}")
    return findings


def cmd_check() -> int:
    findings = check(PICO, DROP_IN, EXT)
    for finding in findings:
        print(f"  drop-in-header FAIL: {finding}", file=sys.stderr)
    if findings:
        return 1
    print(f"  drop-in-header: {DROP_IN.name} declares only zenoh-pico's functions at the pin; "
          f"{EXT.name} declares only {EXT_PREFIX}*")
    return 0


def cmd_selftest() -> int:
    ok = bad = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  drop-in-header selftest FAIL: {name}", file=sys.stderr)

    expect("a declaration, a pointer return and a definition are functions; calls are not",
           declared_functions("int z_a(void);\nchar *z_b(int x);\nstatic inline int z_c(void) "
                              "{ return z_d(1) + z_e(2); }\nint x = z_f(3);\n") == {"z_a", "z_b", "z_c"})
    expect("CMake's defaults are read, quoted or not",
           cmake_defaults('set(Z_FEATURE_A 1 CACHE STRING "x")\nset(FRAG 4096 CACHE STRING "y")\n'
                          'set(P "a b" CACHE STRING "z")\nset(NOT_CACHED 1)\n')
           == {"Z_FEATURE_A": "1", "FRAG": "4096", "P": "a b"})
    template = '#define A @A@\n#cmakedefine B "@B@"\n#cmakedefine C\n'
    expect("a template renders its values, and a #cmakedefine follows CMake's truth",
           render_config(template, {"A": "3", "B": "", "C": "1"})
           == '#define A 3\n/* #undef B */\n#define C\n')
    if shutil.which("cc") is None:
        print("  drop-in-header selftest: the arms on a header tree need `cc`, which is not on PATH",
              file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        pico = root / "pico"
        (pico / "include" / "zenoh-pico").mkdir(parents=True)
        (pico / "CMakeLists.txt").write_text(
            'set(Z_FEATURE_MULTI_THREAD 1 CACHE STRING "t")\nset(Z_FEATURE_EXTRA 0 CACHE STRING "e")\n'
            'set(Z_FEATURE_LINK_TLS 0 CACHE STRING "tls")\n', encoding="utf-8")
        (pico / "include" / "zenoh-pico" / "config.h.in").write_text(
            "#define Z_FEATURE_MULTI_THREAD @Z_FEATURE_MULTI_THREAD@\n"
            "#define Z_FEATURE_EXTRA @Z_FEATURE_EXTRA@\n"
            "#define Z_FEATURE_LINK_TLS @Z_FEATURE_LINK_TLS@\n", encoding="utf-8")
        (pico / "include" / "zenoh-pico.h").write_text(
            '#include "zenoh-pico/config.h"\n#define OWNED(t) int z_##t##_drop(void);\nOWNED(slice)\n'
            "#if Z_FEATURE_MULTI_THREAD == 1\nint z_mutex_lock(void);\n#else\nint z_single(void);\n#endif\n"
            "#if Z_FEATURE_EXTRA == 1\nint z_extra(void);\n#endif\n"
            '#if Z_FEATURE_LINK_TLS == 1\n#include "mbedtls/ssl.h"\n#endif\n', encoding="utf-8")
        drop_in = root / "drop.h"
        ext = root / "wz_ext.h"
        ext.write_text("int wz_ext_watch(void);\n", encoding="utf-8")

        def findings(drop_text: str) -> list[str]:
            drop_in.write_text(drop_text, encoding="utf-8")
            return check(pico, drop_in, ext)

        clean = "int z_slice_drop(void);\nint z_mutex_lock(void);\nint z_single(void);\nint z_extra(void);\n"
        expect("macro-made, multi-threaded, single-threaded and switched-on functions are upstream's",
               findings(clean) == [])
        expect("a function upstream does not declare is a finding",
               any("z_invented" in f for f in findings(clean + "int z_invented(void);\n")))
        expect("a wz door in the drop-in header is pointed to wz_ext.h",
               any("belongs in wz_ext.h" in f for f in findings(clean + "int wz_ext_watch(void);\n")))
        expect("an empty drop-in header is a finding, not a pass",
               any("declares no function" in f for f in findings("/* nothing */\n")))
        ext.write_text("int wz_watch(void);\n", encoding="utf-8")
        expect("a function in wz_ext.h without the prefix is a finding",
               any("not wz_ext_*" in f for f in findings(clean)))
        ext.write_text("int wz_ext_watch(void);\n", encoding="utf-8")
        (pico / "include" / "zenoh-pico.h").write_text(
            (pico / "include" / "zenoh-pico.h").read_text().replace('#include "mbedtls/ssl.h"\n', ""),
            encoding="utf-8")
        expect("a switch listed as needing a library that now preprocesses is a finding",
               any("preprocesses now" in f for f in findings(clean)))
    print(f"  drop-in-header selftest: {ok}/{ok + bad} arm(s) pass")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return cmd_selftest()
    if not argv:
        return cmd_check()
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
