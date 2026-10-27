#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3779 (no register item) -- the facility oracle (docs/target-build-contract.md T9): what a run
of an artifact asks of the operating system, observed, in the words of the facility vocabulary.

`requires` and `may_require` are a must and a may analysis: the first claims what every run asks
for, the second bounds what any run may ask for. Both are derived from a declaration, and a
declaration can be wrong both ways (a facility the code uses and no row names, a facility a row
names that the code never asks for). This module is the ground truth they are judged against: it
runs the artifact under strace(1), reads what each thread asked for, and gives every observed
event exactly one of three classes.

  a FACILITY   one of `wz_config.OS_FACILITIES`, by the witness of that facility below;
  an EXEMPTION something the C library, the loader or the language runtime does on its own
               behalf and does without when it cannot, each with the reason it is not the
               artifact's request (`EXEMPTIONS`);
  UNCLASSIFIED anything else: a finding, which either names a facility the vocabulary lacks or a
               witness or exemption this table lacks. The class is closed on purpose: an event
               nothing explains is not quietly dropped.

What a trace cannot see, the witness shim (`facility_witness_shim.c`, LD_PRELOAD) marks: a read of
the calendar time goes through the vDSO and makes no system call, and the C library's interface
listing and name resolution are system calls that do not say what they are for. A mark is a
faccessat(2) of a path under `/wz-facility-witness/`; `enter/X` and `leave/X` bracket a scope whose
events are given to X, and `point/X` is a use of X.

A judgement (`judge`) holds an observation to a derivation: every facility in `requires` was asked
for (the must analysis is sound for this run), every facility asked for is in `requires` or
`may_require` (the may analysis is sound for this run), and nothing is unclassified.

The witnesses are Linux's (the system calls glibc and the Rust standard library make for each
facility); a platform with other system calls has other witnesses, and none is written yet.

Usage:
    facility_trace.py --selftest
    facility_trace.py --run [--seconds S] -- COMMAND [ARG...]
        Runs COMMAND under the oracle, stops it with SIGINT after S seconds (default: when it
        exits), and prints the observation as JSON.
    facility_trace.py --judge PACKAGE_DIR
        Runs every artifact of a package that has scenarios (`SCENARIOS`) and judges each run
        against the artifact's own manifest entry; an artifact with none is reported NOT JUDGED.
"""

from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import elf_facts  # noqa: E402
import wz_config  # noqa: E402

SHIM_SOURCE = pathlib.Path(__file__).resolve().parent / "facility_witness_shim.c"
MARK_ROOT = "/wz-facility-witness/"

# The system calls the oracle reads. A call outside this list is not seen; within it, every call is
# classified (an `ioctl` that is not an interface request is the one kind read and passed over,
# since strace cannot select ioctls by request: terminal and non-blocking requests ask nothing of
# the vocabulary).
TRACED = ("clone", "clone3", "fork", "vfork", "socket", "connect", "bind", "sendto", "sendmsg",
          "setsockopt", "ioctl", "getrandom", "open", "openat", "openat2", "faccessat", "faccessat2",
          "access")

# What each facility is, observed on Linux. Documentation of `classify_event`, which is what applies
# it, and held to the vocabulary by the selftest (a facility with no witness is never observed).
WITNESSES = {
    "threads": "clone or clone3 with CLONE_THREAD",
    "sockets-tcp": "socket(AF_INET or AF_INET6, SOCK_STREAM)",
    "sockets-udp": "socket(AF_INET or AF_INET6, SOCK_DGRAM)",
    "multicast": "a membership setsockopt (IP_ADD_MEMBERSHIP, IPV6_ADD_MEMBERSHIP, MCAST_JOIN_*), "
                 "or a connect or send to a multicast address",
    "raw-ethernet": "socket(AF_PACKET)",
    "unix-sockets": "socket(AF_UNIX, SOCK_STREAM)",
    "filesystem": "an open of a path that no exemption and no other witness explains",
    "entropy": "getrandom of one byte or more, or an open of /dev/urandom or /dev/random",
    "wall-clock": "the shim's mark of clock_gettime(CLOCK_REALTIME, _COARSE or CLOCK_TAI), "
                  "gettimeofday or time, or its scope of localtime, localtime_r or tzset (the zone "
                  "database they read is inside it)",
    "interface-list": "the shim's scope of getifaddrs, if_nametoindex or if_indextoname, or an "
                      "interface ioctl (SIOCGIF*)",
    "name-resolution": "the shim's scope of getaddrinfo (the files it reads and the DNS it asks are "
                       "inside it)",
}

# What the C library, the loader and the language runtime do for themselves, and why each is not
# a request of the artifact: each is either done before the artifact runs or done without when the
# operating system refuses it.
EXEMPTIONS = {
    "loader": "the dynamic loader opens ld.so.cache and the shared objects of the artifact's NEEDED "
              "closure before the artifact runs; what a device must hold for that is T5's, by "
              "SONAME",
    "glibc-tcache-key": "glibc (2.34 and later) seeds its malloc tcache key with one 8-byte "
                        "non-blocking getrandom per process and uses a fixed key when it fails",
    "zero-length-probe": "a getrandom of zero bytes draws nothing: it asks whether the call exists",
    "thread-stack-probe": "glibc's pthread_getattr_np reads /proc/self/maps to find the main thread's "
                          "stack; the Rust runtime calls it for the guard page and goes on without",
    "cpu-quota-probe": "std::thread::available_parallelism reads the cgroup CPU quota "
                       "(/proc/self/cgroup, /proc/self/mountinfo, /sys/fs/cgroup) and keeps the "
                       "affinity count when it cannot",
    "glibc-heap-shrink-probe": "glibc reads /proc/sys/vm/overcommit_memory the first time it shrinks "
                               "a thread arena's heap (check_may_shrink_heap) and does not shrink it "
                               "when the read fails; whether a run reaches it depends on its "
                               "allocations, and the path is in libc.so.6 and in no wz binary",
}
GLIBC_PROBE_PATHS = ("/proc/sys/vm/overcommit_memory",)
CPU_QUOTA_PATHS = ("/proc/self/cgroup", "/proc/self/mountinfo")
CPU_QUOTA_PREFIXES = ("/sys/fs/cgroup/",)
LOADER_PATHS = ("/etc/ld.so.cache", "/etc/ld.so.preload")
ENTROPY_DEVICES = ("/dev/urandom", "/dev/random")

# A scope of the shim is given to a facility, to an exemption, or (a name in neither) is itself the
# unclassified finding. Name resolution was the first such finding, and is a facility since.
SCOPE_EXEMPTIONS = {"thread-stack-probe"}

MEMBERSHIP_OPTIONS = ("IP_ADD_MEMBERSHIP", "IP_ADD_SOURCE_MEMBERSHIP", "IPV6_ADD_MEMBERSHIP",
                      "IPV6_JOIN_GROUP", "MCAST_JOIN_GROUP", "MCAST_JOIN_SOURCE_GROUP")
INET4_RE = re.compile(r'inet_addr\("(\d+)\.\d+\.\d+\.\d+"\)')
INET6_RE = re.compile(r'inet_pton\(AF_INET6, "([0-9a-fA-F:.]*)"')
LINE_RE = re.compile(r"^(?P<call>\w+)\((?P<args>.*)\)\s+=\s+(?P<ret>.*)$")
STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


@dataclasses.dataclass
class Observation:
    """What one run asked for: each facility with the first event that witnessed it, each exemption
    with how often it applied, and every unclassified event; and how the run ended: `stopped` when
    the oracle ended it, otherwise its exit status, with the tail of what it wrote to stderr."""
    facilities: dict[str, str] = dataclasses.field(default_factory=dict)
    exempt: dict[str, int] = dataclasses.field(default_factory=dict)
    unclassified: list[str] = dataclasses.field(default_factory=list)
    stopped: bool = False
    exit_status: int | None = None
    stderr_tail: str = ""
    stdout: str = ""
    # What the scenario's `stated_by` door answered for the run's configuration, when it has one.
    stated: str = ""

    def add(self, kind: str, name: str, evidence: str) -> None:
        if kind == "facility":
            self.facilities.setdefault(name, evidence)
        elif kind == "exempt":
            self.exempt[name] = self.exempt.get(name, 0) + 1
        elif kind == "unclassified":
            self.unclassified.append(f"{name}: {evidence}")
        elif kind != "ignored":
            raise ValueError(f"no class {kind!r}")

    def as_json(self) -> dict:
        return {"facilities": sorted(self.facilities), "evidence": dict(sorted(self.facilities.items())),
                "exempt": dict(sorted(self.exempt.items())), "unclassified": self.unclassified}


def parse_line(line: str) -> tuple[str, str, str] | None:
    """A traced call as (name, arguments, result), or None for strace's own lines (exits, signals)."""
    line = line.rstrip("\n")
    if not line or line.startswith(("+++", "---")):
        return None
    match = LINE_RE.match(line)
    if match is None:
        raise ValueError(f"not a traced call: {line!r}")
    return match["call"], match["args"], match["ret"]


def first_string(args: str) -> str | None:
    match = STRING_RE.search(args)
    return None if match is None else bytes(match[1], "utf-8").decode("unicode_escape")


def is_multicast_destination(args: str) -> bool:
    v4 = INET4_RE.search(args)
    if v4 and 224 <= int(v4[1]) <= 239:
        return True
    v6 = INET6_RE.search(args)
    return bool(v6 and v6[1].lower().startswith("ff"))


def classify_event(call: str, args: str, ret: str, loader_names: set[str]) -> tuple[str, str]:
    """One traced call, outside every scope of the shim, as (class, name)."""
    if call in ("clone", "clone3"):
        return ("facility", "threads") if "CLONE_THREAD" in args else ("unclassified", "process")
    if call in ("fork", "vfork"):
        return "unclassified", "process"
    if call == "socket":
        domain, _, rest = args.partition(", ")
        kind = rest.split(", ")[0].split("|")[0]
        if domain in ("AF_INET", "AF_INET6") and kind == "SOCK_STREAM":
            return "facility", "sockets-tcp"
        if domain in ("AF_INET", "AF_INET6") and kind == "SOCK_DGRAM":
            return "facility", "sockets-udp"
        if domain == "AF_PACKET":
            return "facility", "raw-ethernet"
        if domain == "AF_UNIX" and kind == "SOCK_STREAM":
            return "facility", "unix-sockets"
        return "unclassified", f"socket {domain} {kind}"
    if call == "setsockopt":
        if any(option in args for option in MEMBERSHIP_OPTIONS):
            return "facility", "multicast"
        return "ignored", "socket option"
    if call in ("connect", "sendto", "sendmsg", "bind"):
        if call != "bind" and is_multicast_destination(args):
            return "facility", "multicast"
        return "ignored", "an address on a socket already classified"
    if call == "ioctl":
        return ("facility", "interface-list") if "SIOCGIF" in args else ("ignored", "ioctl")
    if call == "getrandom":
        fields = [f.strip() for f in args.rsplit(", ", 2)]
        length, flags = (fields[1], fields[2]) if len(fields) == 3 else ("", "")
        if length == "0":
            return "exempt", "zero-length-probe"
        if length == "8" and flags == "GRND_NONBLOCK":
            return "exempt", "glibc-tcache-key"
        return "facility", "entropy"
    if call in ("open", "openat", "openat2"):
        path = first_string(args) or ""
        if path in LOADER_PATHS or pathlib.PurePosixPath(path).name in loader_names:
            return "exempt", "loader"
        if path in ENTROPY_DEVICES:
            return "facility", "entropy"
        if path in CPU_QUOTA_PATHS or path.startswith(CPU_QUOTA_PREFIXES):
            return "exempt", "cpu-quota-probe"
        if path in GLIBC_PROBE_PATHS:
            return "exempt", "glibc-heap-shrink-probe"
        return "facility", "filesystem"
    if call in ("faccessat", "faccessat2", "access"):
        if (first_string(args) or "") in LOADER_PATHS:
            return "exempt", "loader"
        return "facility", "filesystem"
    raise ValueError(f"the oracle traces {call} and has no rule for it")


def mark_of(call: str, args: str) -> tuple[str, str] | None:
    """The shim's mark a call is, as (`enter`, `leave` or `point`, name), or None."""
    if call not in ("faccessat", "faccessat2", "access"):
        return None
    path = first_string(args) or ""
    if not path.startswith(MARK_ROOT):
        return None
    kind, _, name = path[len(MARK_ROOT):].partition("/")
    if kind not in ("enter", "leave", "point") or not name:
        raise ValueError(f"a mark the shim does not make: {path}")
    return kind, name


def scope_class(name: str) -> tuple[str, str]:
    if name in wz_config.OS_FACILITIES:
        return "facility", name
    if name in SCOPE_EXEMPTIONS:
        return "exempt", name
    return "unclassified", name


def classify_thread(lines: list[str], loader_names: set[str], seen: Observation) -> None:
    """Every call of one thread's trace, in order, into `seen`. A call inside a scope of the shim is
    the scope's; a scope reported unclassified is reported once per entry, not once per call."""
    stack: list[str] = []
    for line in lines:
        parsed = parse_line(line)
        if parsed is None:
            continue
        call, args, ret = parsed
        mark = mark_of(call, args)
        if mark is not None:
            kind, name = mark
            if kind == "enter":
                if not stack:
                    seen.add(*scope_class(name), line.strip())
                stack.append(name)
            elif kind == "leave":
                if not stack or stack[-1] != name:
                    raise ValueError(f"the shim left {name} it did not enter: {line.strip()}")
                stack.pop()
            else:
                seen.add(*scope_class(name), line.strip())
            continue
        if stack:
            continue
        seen.add(*classify_event(call, args, ret, loader_names), line.strip())


def loader_closure(binary: pathlib.Path, opened: list[pathlib.Path]) -> set[str]:
    """The SONAMEs the loader brings in for `binary`: its NEEDED, and the NEEDED of each shared
    object of that set the trace shows opened, to a fixed point; with the shim, which the oracle
    preloads."""
    names = set(elf_facts.dynamic_facts(binary.read_bytes())["needed"]) | {"facility_witness_shim.so"}
    by_name = {p.name: p for p in opened if p.is_file()}
    pending = [n for n in names if n in by_name]
    read: set[str] = set()
    while pending:
        name = pending.pop()
        if name in read:
            continue
        read.add(name)
        for needed in elf_facts.dynamic_facts(by_name[name].read_bytes())["needed"]:
            if needed not in names:
                names.add(needed)
                if needed in by_name:
                    pending.append(needed)
    return names


def build_shim(work: pathlib.Path) -> pathlib.Path:
    out = work / "facility_witness_shim.so"
    subprocess.run(["cc", "-shared", "-fPIC", "-O2", "-Wall", "-Werror", "-o", str(out), str(SHIM_SOURCE),
                    "-ldl"], check=True)
    return out


def missing_tools() -> list[str]:
    return [tool for tool in ("strace", "cc") if shutil.which(tool) is None]


def stop_tracee(strace: subprocess.Popen) -> None:
    """End a traced run that has not ended by itself, and wait for strace to write its last line.

    The signal goes to the traced program, strace's child, and not to strace: strace started as
    `-o FILE PROG` blocks the fatal signals (its `-I3`), so a signal to it reaches nothing (measured
    on a build machine's service unit, where the run outlived 30 seconds of waiting). strace exits
    when its tracee does. A program that ignores SIGINT is asked again with SIGTERM, then killed.
    """
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
        children = pathlib.Path(f"/proc/{strace.pid}/task/{strace.pid}/children")
        try:
            pids = [int(p) for p in children.read_text(encoding="ascii").split()]
        except OSError:
            pids = []
        for pid in pids:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
        try:
            strace.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue
    strace.kill()
    strace.wait()


def observe(command: list[str], seconds: float | None = None, env: dict[str, str] | None = None) -> Observation:
    """Run `command` under the oracle and classify every traced call of every thread it ran."""
    with tempfile.TemporaryDirectory(prefix="wz-facility-") as tmp:
        work = pathlib.Path(tmp)
        shim = build_shim(work)
        prefix = work / "trace"
        argv = ["strace", "-ff", "-qq", "-s", "4096", "-e", "signal=none", "-e", f"trace={','.join(TRACED)}",
                "-o", str(prefix), "-E", f"LD_PRELOAD={shim}"]
        for key, value in (env or {}).items():
            argv += ["-E", f"{key}={value}"]
        # strace writes the trace to its files and passes the program's own stderr through, so what
        # the stderr file holds is the program's; strace's exit status is the program's.
        stderr_path = work / "stderr"
        stdout_path = work / "stdout"
        with stderr_path.open("wb") as stderr, stdout_path.open("wb") as stdout:
            proc = subprocess.Popen(argv + ["--", *command], stdout=stdout, stderr=stderr)
            stopped = False
            try:
                proc.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                stop_tracee(proc)
                stopped = True
        files = sorted(work.glob("trace.*"), key=lambda p: int(p.suffix[1:]))
        threads = [p.read_text(encoding="utf-8", errors="backslashreplace").splitlines() for p in files]
        binary = pathlib.Path(shutil.which(command[0]) or command[0]).resolve()
        opened = [pathlib.Path(s) for lines in threads for line in lines
                  if line.startswith(("open", "openat")) and not re.search(r"= -1 ", line)
                  for s in [first_string(line) or ""] if s.endswith(".so") or ".so." in s]
        names = loader_closure(binary, opened)
        seen = Observation(stopped=stopped, exit_status=None if stopped else proc.returncode,
                           stderr_tail=stderr_path.read_text(encoding="utf-8", errors="replace")[-600:],
                           stdout=stdout_path.read_text(encoding="utf-8", errors="replace"))
        for lines in threads:
            classify_thread(lines, names, seen)
        return seen


DRIVERS = pathlib.Path(__file__).resolve().parent / "facility_drivers"
ROOT = pathlib.Path(__file__).resolve().parents[2]


@dataclasses.dataclass(frozen=True)
class Driver:
    """The program a library runs inside: a C source of `facility_drivers/`, compiled against the
    packaged library itself (and the include directories of the tree, when the source includes a
    header of them) and run with the library's directory on the loader's path."""
    source: str
    include: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class Scenario:
    """One run of a packaged artifact under the oracle: the traced command and, when the run needs
    a counterpart to open a session, the untraced peer's. `{bin}` is the artifact's file, or the
    driver compiled against it for a library; `{package}` is the package's directory, so a peer can
    be another artifact of the same package; `{port}` and `{port2}` are free local ports, and
    `{work}` the run's own directory (where a TLS scenario's material is). A peer that listens
    starts first; one that dials starts after the traced run has had time to listen. A run that has
    not ended by itself is stopped after `seconds`."""
    name: str
    traced: tuple[str, ...]
    peer: tuple[str, ...] = ()
    peer_listens: bool = False
    seconds: float = 5.0
    driver: Driver | None = None
    # A certificate authority and a server certificate for 127.0.0.1, made for the run in `{work}`
    # (`ca.pem`, `server.pem`, `server.key`), for a scenario whose links are TLS.
    tls: bool = False
    # Files written in `{work}` before the run, as (name, text). The text takes `{port}` and
    # `{port2}` replaced literally, since a document's own braces are not templates.
    documents: tuple[tuple[str, str], ...] = ()
    # An untraced command run before the traced one, whose stdout is the requirement of the run's
    # configuration (a door that answers apart from the run, as ap-demo's `--device-requires`).
    stated_by: tuple[str, ...] = ()


def library_scenarios(driver: Driver) -> tuple[Scenario, ...]:
    """A library's two runs, as a peer that the package's ap-demo dials and as a client that dials
    the package's ap-demo; the driver puts for three seconds and closes the session itself."""
    demo = "{package}/bin/wz-ap-demo"
    return (
        Scenario("a peer that listens and that ap-demo subscribes to",
                 ("{bin}", "listen", "tcp/127.0.0.1:{port}", "3"),
                 (demo, "--connect", "tcp/127.0.0.1:{port}", "--key", "demo/x"), seconds=15.0, driver=driver),
        Scenario("a client that dials ap-demo and publishes",
                 ("{bin}", "connect", "tcp/127.0.0.1:{port}", "3"),
                 (demo, "--listen", "tcp/127.0.0.1:{port}", "--key", "demo/x"), peer_listens=True,
                 seconds=15.0, driver=driver),
        Scenario("a client that dials ap-demo by host name",
                 ("{bin}", "connect", "tcp/localhost:{port}", "3"),
                 (demo, "--listen", "tcp/127.0.0.1:{port}", "--key", "demo/x"), peer_listens=True,
                 seconds=15.0, driver=driver),
    )


def configuration_corpus(driver: Driver) -> tuple[Scenario, ...]:
    """The zenoh-c runs that hold each branch of a configuration's derivation to a run
    (`OpenPlan::device_requires`): a TLS dial whose material is files, a client that can only find
    its node by scouting, and a listener allowed to fail. The peer is the driver itself, on the same
    library. Scouting goes to a group port of the run's own (`{port2}`), so no other node on the
    network can answer it."""
    peer_lib = "{bin}"
    group = 'scouting/multicast/address="224.0.0.224:{port2}"'
    return (
        Scenario("a client that dials over TLS with its trust anchor in a file",
                 (peer_lib, "connect", "tls/127.0.0.1:{port}", "3",
                  'transport/link/tls/root_ca_certificate="{work}/ca.pem"'),
                 (peer_lib, "listen", "tls/127.0.0.1:{port}", "12",
                  'transport/link/tls/listen_certificate="{work}/server.pem"',
                  'transport/link/tls/listen_private_key="{work}/server.key"'),
                 peer_listens=True, seconds=15.0, driver=driver, tls=True),
        Scenario("a client that finds its node only by scouting",
                 (peer_lib, "connect", "-", "3", group),
                 (peer_lib, "listen", "tcp/127.0.0.1:{port}", "12", group),
                 peer_listens=True, seconds=15.0, driver=driver),
        Scenario("a listener allowed to fail its bind",
                 (peer_lib, "listen", "tcp/127.0.0.1:{port}", "3", "listen/exit_on_failure=false"),
                 ("{package}/bin/wz-ap-demo", "--connect", "tcp/127.0.0.1:{port}", "--key", "demo/x"),
                 seconds=15.0, driver=driver),
    )


def make_tls_material(work: pathlib.Path) -> None:
    """A certificate authority and a server certificate it signed for 127.0.0.1, in `work`."""
    def openssl(*args: str) -> None:
        subprocess.run(["openssl", *args], cwd=work, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)

    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
            "-days", "2", "-subj", "/CN=wz facility oracle CA")
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr",
            "-subj", "/CN=127.0.0.1")
    (work / "san.ext").write_text("subjectAltName=IP:127.0.0.1\n", encoding="utf-8")
    openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
            "-out", "server.pem", "-days", "2", "-extfile", "san.ext")


# The runs each artifact is judged on, by its manifest id. A scenario must reach what `requires`
# claims every run asks for, so each opens a session (or, for a node whose router is a lab address,
# reaches its dial), and it may reach any part of the bound.
# ap-demo's `--sessions` run, judged against what its `--device-requires` answers for the same
# document: a listening session and a dialling one whose only target is named by host.
SESSIONS_DOCUMENT = """{
    sessions: [
        { name: "inbound", mode: "peer", transport: "unicast", zid: "ee02",
          listen: { endpoints: ["tcp/127.0.0.1:{port2}"] } },
        { name: "to_peer", mode: "client", transport: "unicast", zid: "ee01",
          connect: { endpoints: ["tcp/localhost:{port}"] } },
    ],
}
"""

SCENARIOS = {
    "capi-pico": library_scenarios(Driver("pico_session.c",
                                          ("crates/wz-capi-pico/include", "crates/wz-capi-core/include"))),
    "capi-c": library_scenarios(Driver("c_session.c")) + configuration_corpus(Driver("c_session.c")),
    "ap-demo": (
        Scenario("a listener that a peer publishes to",
                 ("{bin}", "--listen", "tcp/127.0.0.1:{port}", "--key", "demo/x"),
                 ("{bin}", "--connect", "tcp/127.0.0.1:{port}", "--publish", "demo/x", "--value", "v")),
        Scenario("a connector that publishes to a listener",
                 ("{bin}", "--connect", "tcp/127.0.0.1:{port}", "--publish", "demo/x", "--value", "v"),
                 ("{bin}", "--listen", "tcp/127.0.0.1:{port}", "--key", "demo/x"), peer_listens=True),
        Scenario("a sessions document: a listener, and a dial by host name to a peer",
                 ("{bin}", "--sessions", "{work}/sessions.json5"),
                 ("{bin}", "--listen", "tcp/127.0.0.1:{port}", "--key", "demo/x"), peer_listens=True,
                 seconds=8.0, documents=(("sessions.json5", SESSIONS_DOCUMENT),),
                 stated_by=("{bin}", "--device-requires", "{work}/sessions.json5")),
    ),
    "declared-node": (
        Scenario("a node whose router does not answer", ("{bin}",), seconds=3.0),
    ),
}


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_driver(driver: Driver, library: pathlib.Path, work: pathlib.Path) -> pathlib.Path:
    """The driver compiled against `library` (linked by its file name, so no other copy of it on the
    machine can stand in)."""
    out = work / pathlib.Path(driver.source).stem
    argv = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror"]
    for directory in driver.include:
        argv += ["-I", str(ROOT / directory)]
    argv += [str(DRIVERS / driver.source), "-L", str(library.parent), f"-l:{library.name}", "-o", str(out)]
    subprocess.run(argv, check=True)
    return out


def run_scenario(scenario: Scenario, artifact: pathlib.Path, package: pathlib.Path) -> Observation:
    """The observation of one scenario: the peer is started and stopped around the traced run."""
    with tempfile.TemporaryDirectory(prefix="wz-facility-driver-") as tmp:
        work = pathlib.Path(tmp)
        if scenario.tls:
            make_tls_material(work)
        if scenario.driver is None:
            return _run(scenario, artifact, package, {}, work)
        binary = build_driver(scenario.driver, artifact, work)
        return _run(scenario, binary, package, {"LD_LIBRARY_PATH": str(artifact.parent)}, work)


def _run(scenario: Scenario, binary: pathlib.Path, package: pathlib.Path, env: dict[str, str],
         work: pathlib.Path) -> Observation:
    port, port2 = free_port(), free_port()

    def argv(words: tuple[str, ...]) -> list[str]:
        return [w.format(bin=binary, package=package, port=port, port2=port2, work=work) for w in words]

    for name, text in scenario.documents:
        (work / name).write_text(text.replace("{port}", str(port)).replace("{port2}", str(port2)),
                                 encoding="utf-8")
    stated = ""
    if scenario.stated_by:
        door = subprocess.run(argv(scenario.stated_by), capture_output=True, text=True, timeout=30,
                              env={**os.environ, **env})
        if door.returncode != 0:
            raise ValueError(f"{scenario.name}: the requirement door exited {door.returncode}: "
                             f"{door.stderr.strip()}")
        stated = door.stdout

    peer: list[subprocess.Popen] = []

    def start_peer() -> None:
        # A peer that is the driver needs the library's path as the traced run does.
        peer.append(subprocess.Popen(argv(scenario.peer), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     env={**os.environ, **env}))

    late = None
    if scenario.peer and scenario.peer_listens:
        start_peer()
        time.sleep(1.0)
    elif scenario.peer:
        late = threading.Timer(1.5, start_peer)
        late.start()
    try:
        seen = observe(argv(scenario.traced), scenario.seconds, env)
        seen.stated = stated
        return seen
    finally:
        if late is not None:
            late.cancel()
            late.join()
        for p in peer:
            p.send_signal(signal.SIGINT)
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()


def judge_package(directory: pathlib.Path) -> tuple[list[str], list[str]]:
    """Every artifact of a package that has scenarios, run and judged against its own manifest
    entry: (findings, a line per judgement). A manifest written before the split judges its whole
    bound as `may_require`."""
    manifest = json.loads((directory / "wz-target-manifest.json").read_text(encoding="utf-8"))
    findings: list[str] = []
    report: list[str] = []
    for art in manifest["artifacts"]:
        scenarios = SCENARIOS.get(art["id"])
        if scenarios is None:
            report.append(f"{art['id']}: NOT JUDGED, no scenario runs it")
            continue
        requires = art.get("requires", [])
        may = art.get("may_require", art["device_requires"]) if "requires" in art else art["device_requires"]
        for scenario in scenarios:
            seen = run_scenario(scenario, directory / art["path"], directory)
            found = judge(seen, requires, may)
            findings += [f"{art['id']} ({scenario.name}): {f}" for f in found]
            report.append(f"{art['id']} ({scenario.name}): observed {sorted(seen.facilities)}, "
                          f"{'refuted' if found else 'agrees with'} requires {requires} and may_require {may}")
            stated = stated_requirement(seen.stated) if seen.stated else configuration_requirement(seen.stdout)
            if stated is not None:
                c_requires, c_may = stated
                found = judge(seen, c_requires, c_may)
                findings += [f"{art['id']} ({scenario.name}, for its configuration): {f}" for f in found]
                report.append(f"{art['id']} ({scenario.name}): {'refuted' if found else 'agrees with'} "
                              f"its configuration's requires {c_requires} and may_require {c_may}")
    return findings, report


def configuration_requirement(stdout: str) -> tuple[list[str], list[str] | None] | None:
    """The requirement a run printed for its own configuration, `device_requires <json>` (what a
    library's door answered for the config it opened), or None when it printed none."""
    lines = [line for line in stdout.splitlines() if line.startswith("device_requires ")]
    if not lines:
        return None
    if len(lines) > 1:
        raise ValueError(f"the run printed {len(lines)} device_requires lines, and states one configuration")
    return stated_requirement(lines[0][len("device_requires "):])


def stated_requirement(text: str) -> tuple[list[str], list[str] | None]:
    """A configuration's requirement as a door states it, one JSON object with the manifest's keys."""
    stated = json.loads(text)
    return list(stated["requires"]), stated["may_require"]


def judge(seen: Observation, requires: list[str], may_require: list[str] | None) -> list[str]:
    """What an observation refutes of a derivation: a required facility the run never asked for (the
    must analysis claimed too much), a facility asked for outside the bound (the may analysis
    claimed too little), and each unclassified event. `may_require` None is UNKNOWN: the bound
    cannot be refuted. A run that ended by itself with a failure is a finding first: it stopped
    short of what a run does, so what it asked for stands for nothing."""
    out = []
    if seen.exit_status not in (None, 0):
        out.append(f"the run failed by itself (exit {seen.exit_status}), so it stands for no run: "
                   f"{seen.stderr_tail.strip() or 'it wrote nothing to stderr'}")
    out += [f"requires {f} and the run never asked for it" for f in requires if f not in seen.facilities]
    if may_require is not None:
        bound = set(requires) | set(may_require)
        out += [f"the run asked for {f} outside requires and may_require ({seen.facilities[f]})"
                for f in sorted(seen.facilities) if f not in bound]
    out += [f"unclassified: {u}" for u in seen.unclassified]
    return out


# The selftest's probe: one C program that does exactly one thing, named by its first argument, so
# each facility's witness is observed alone and an empty run is the baseline every other is held to.
PROBE_SOURCE = r"""
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void *nothing(void *arg) { return arg; }

int main(int argc, char **argv) {
    const char *what = argc > 1 ? argv[1] : "none";
    if (!strcmp(what, "threads")) {
        pthread_t t;
        pthread_create(&t, 0, nothing, 0);
        pthread_join(t, 0);
    } else if (!strcmp(what, "sockets-tcp")) {
        close(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    } else if (!strcmp(what, "sockets-udp")) {
        close(socket(AF_INET6, SOCK_DGRAM, 0));
    } else if (!strcmp(what, "multicast")) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        struct ip_mreq m;
        m.imr_multiaddr.s_addr = inet_addr("224.0.0.224");
        m.imr_interface.s_addr = htonl(INADDR_ANY);
        setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof m);
        close(s);
    } else if (!strcmp(what, "raw-ethernet")) {
        socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    } else if (!strcmp(what, "unix-sockets")) {
        close(socket(AF_UNIX, SOCK_STREAM, 0));
    } else if (!strcmp(what, "filesystem")) {
        close(open(argv[2], O_RDONLY));
    } else if (!strcmp(what, "entropy")) {
        char b[16];
        if (getrandom(b, sizeof b, 0) < 0) return 1;
    } else if (!strcmp(what, "wall-clock")) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
    } else if (!strcmp(what, "interface-list")) {
        struct ifaddrs *list;
        if (!getifaddrs(&list)) freeifaddrs(list);
    } else if (!strcmp(what, "name-resolution")) {
        struct addrinfo *res;
        if (!getaddrinfo("localhost", "7447", 0, &res)) freeaddrinfo(res);
    } else if (!strcmp(what, "process")) {
        pid_t p = fork();
        if (p == 0) _exit(0);
        waitpid(p, 0, 0);
    } else if (!strcmp(what, "stack-probe")) {
        pthread_attr_t a;
        pthread_getattr_np(pthread_self(), &a);
        pthread_attr_destroy(&a);
    } else if (!strcmp(what, "local-time")) {
        time_t now = 0;
        struct tm parts;
        localtime_r(&now, &parts);
    } else if (!strcmp(what, "monotonic")) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
    } else if (!strcmp(what, "wait")) {
        pause();
    } else if (!strcmp(what, "stubborn")) {
        signal(SIGINT, SIG_IGN);
        pause();
    }
    return 0;
}
"""


def _selftest() -> int:
    failures: list[str] = []

    def expect(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    expect("every facility of the vocabulary has a witness, and nothing else does",
           set(WITNESSES) == set(wz_config.OS_FACILITIES))
    expect("a line of strace parses to its call, arguments and result",
           parse_line('openat(AT_FDCWD, "/a b", O_RDONLY) = 3') == ("openat", 'AT_FDCWD, "/a b", O_RDONLY', "3"))
    expect("strace's own lines are not calls", parse_line("+++ exited with 0 +++") is None)
    expect("a multicast destination is one by its address",
           is_multicast_destination('{sa_family=AF_INET, sin_port=htons(7446), sin_addr=inet_addr("224.0.0.224")}')
           and not is_multicast_destination('{sa_family=AF_INET, sin_addr=inet_addr("192.0.2.1")}')
           and is_multicast_destination('inet_pton(AF_INET6, "ff02::1", &sin6_addr)'))
    expect("a thread is a clone with CLONE_THREAD and a process is one without",
           classify_event("clone3", "{flags=CLONE_VM|CLONE_THREAD}", "5", set()) == ("facility", "threads")
           and classify_event("clone", "child_stack=NULL, flags=SIGCHLD", "5", set())[0] == "unclassified")
    expect("an open of a NEEDED object is the loader's, any other open is a file",
           classify_event("openat", 'AT_FDCWD, "/lib/libc.so.6", O_RDONLY', "3", {"libc.so.6"})
           == ("exempt", "loader")
           and classify_event("openat", 'AT_FDCWD, "/lib/libplugin.so", O_RDONLY', "3", {"libc.so.6"})
           == ("facility", "filesystem"))
    expect("glibc's heap-shrink probe is exempt and a neighbouring /proc/sys file is not",
           classify_event("openat", 'AT_FDCWD, "/proc/sys/vm/overcommit_memory", O_RDONLY', "3", set())
           == ("exempt", "glibc-heap-shrink-probe")
           and classify_event("openat", 'AT_FDCWD, "/proc/sys/vm/swappiness", O_RDONLY', "3", set())
           == ("facility", "filesystem"))
    expect("the shim's marks are read as marks",
           mark_of("faccessat", f'AT_FDCWD, "{MARK_ROOT}enter/interface-list", F_OK') == ("enter", "interface-list"))
    stacked = Observation()
    classify_thread([f'faccessat(AT_FDCWD, "{MARK_ROOT}enter/name-resolution", F_OK) = -1 ENOENT',
                     'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3',
                     f'faccessat(AT_FDCWD, "{MARK_ROOT}leave/name-resolution", F_OK) = -1 ENOENT',
                     f'faccessat(AT_FDCWD, "{MARK_ROOT}enter/mount-table", F_OK) = -1 ENOENT',
                     'openat(AT_FDCWD, "/proc/self/mounts", O_RDONLY) = 3',
                     f'faccessat(AT_FDCWD, "{MARK_ROOT}leave/mount-table", F_OK) = -1 ENOENT'],
                    set(), stacked)
    expect("what a scope brackets is the scope's, and a scope outside the vocabulary is unclassified once",
           list(stacked.facilities) == ["name-resolution"] and len(stacked.unclassified) == 1
           and stacked.unclassified[0].startswith("mount-table"))
    seen = Observation()
    seen.add("facility", "entropy", "e")
    seen.add("facility", "sockets-udp", "u")
    expect("a judgement finds a required facility the run did not ask for and one outside the bound",
           judge(seen, ["entropy", "threads"], ["sockets-tcp"])
           == ["requires threads and the run never asked for it",
               "the run asked for sockets-udp outside requires and may_require (u)"])
    expect("an unknown bound cannot be refuted, a lower bound still can",
           judge(seen, ["entropy"], None) == [])
    failed_run = dataclasses.replace(seen, exit_status=1, stderr_tail="z_open returned -1\n")
    expect("a run's own configuration requirement is read from its line, and a run without one has none",
           configuration_requirement('x\ndevice_requires {"requires": ["entropy"], "may_require": null, '
                                     '"unknown": ["serial"]}\n') == (["entropy"], None)
           and configuration_requirement("nothing\n") is None)
    expect("a run's other lines are not a configuration requirement",
           configuration_requirement("requires entropy\n") is None)
    expect("a run that failed by itself is a finding, with what it said",
           judge(failed_run, ["entropy"], None)
           == ["the run failed by itself (exit 1), so it stands for no run: z_open returned -1"])

    missing = missing_tools()
    if missing:
        print(f"facility-trace selftest: the traced arms SKIP, {' and '.join(missing)} absent")
    else:
        with tempfile.TemporaryDirectory(prefix="wz-facility-probe-") as tmp:
            work = pathlib.Path(tmp)
            (work / "probe.c").write_text(PROBE_SOURCE, encoding="utf-8")
            probe = work / "probe"
            subprocess.run(["cc", "-O1", "-Wall", "-Werror", "-o", str(probe), str(work / "probe.c"), "-lpthread"],
                           check=True)
            (work / "file").write_text("x", encoding="utf-8")

            def observed(*args: str) -> Observation:
                return observe([str(probe), *args])

            base = observed("none")
            expect(f"a program that does nothing asks for nothing ({base.as_json()})",
                   base.facilities == {} and base.unclassified == [] and base.exempt.get("loader", 0) > 0
                   and not base.stopped and base.exit_status == 0)
            for facility, args, also in (
                ("threads", (), set()),
                ("sockets-tcp", (), set()),
                ("sockets-udp", (), set()),
                ("multicast", (), {"sockets-udp"}),
                ("raw-ethernet", (), set()),
                ("unix-sockets", (), set()),
                ("filesystem", (str(work / "file"),), set()),
                ("entropy", (), set()),
                ("wall-clock", (), set()),
                ("interface-list", (), set()),
                ("name-resolution", (), set()),
            ):
                got = observed(facility, *args)
                expect(f"the witness of {facility} sees it and nothing else ({got.as_json()})",
                       set(got.facilities) == {facility} | also and got.unclassified == [])
            got = observed("process")
            expect(f"starting a process is outside the vocabulary and is a finding ({got.as_json()})",
                   got.facilities == {} and len(got.unclassified) == 1 and got.unclassified[0].startswith("process"))
            stack = observed("stack-probe")
            expect(f"the C library's stack probe is exempt ({stack.as_json()})",
                   stack.facilities == {} and stack.unclassified == [] and stack.exempt.get("thread-stack-probe") == 1)
            local = observed("local-time")
            expect(f"a local time is the calendar's, zone file and all ({local.as_json()})",
                   set(local.facilities) == {"wall-clock"} and local.unclassified == [])
            mono = observed("monotonic")
            expect(f"a monotonic clock is not the calendar ({mono.as_json()})", mono.facilities == {})
            for what in ("wait", "stubborn"):
                started = time.monotonic()
                stopped = observe([str(probe), what], seconds=0.5)
                expect(f"a run that does not end by itself ({what}) is stopped and read "
                       f"({stopped.as_json()}, {time.monotonic() - started:.1f}s)",
                       stopped.facilities == {} and stopped.unclassified == [] and stopped.stopped
                       and stopped.exit_status is None and time.monotonic() - started < 25)

    for label in failures:
        print(f"facility-trace: FAIL -- selftest: {label}")
    if failures:
        return 1
    print("facility-trace: selftest OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return _selftest()
    if argv and argv[0] == "--run":
        rest = argv[1:]
        seconds = None
        if rest[:1] == ["--seconds"]:
            seconds, rest = float(rest[1]), rest[2:]
        if rest[:1] != ["--"] or len(rest) < 2:
            print(__doc__, file=sys.stderr)
            return 2
        missing = missing_tools()
        if missing:
            print(f"facility-trace: {' and '.join(missing)} absent", file=sys.stderr)
            return 2
        print(json.dumps(observe(rest[1:], seconds).as_json(), indent=2))
        return 0
    if len(argv) == 2 and argv[0] == "--judge":
        missing = missing_tools()
        if missing:
            print(f"facility-trace: FAIL -- {' and '.join(missing)} absent, so no run can be judged", file=sys.stderr)
            return 1
        findings, report = judge_package(pathlib.Path(argv[1]))
        for line in report:
            print(f"  facility-trace: {line}")
        for finding in findings:
            print(f"facility-trace: FAIL -- {finding}")
        return 1 if findings else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
