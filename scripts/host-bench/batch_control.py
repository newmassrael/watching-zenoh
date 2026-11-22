#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The unicast batch size on the wire, zenoh-pico against the wz pico ABI (`scripts/pico-compare.sh batch`).

zenoh-pico fixes its unicast batch size when it is built: `BATCH_UNICAST_SIZE`, which its CMake writes into
`config.h` as `Z_BATCH_UNICAST_SIZE` (`vendor/zenoh-pico/cmake/feature_config.cmake` @
`set(BATCH_UNICAST_SIZE 2048 CACHE STRING "Use this to override the maximum unicast batch size")`). A session of the wz
pico ABI takes it from the `wz/limits` of its configuration document (`PICO_UNICAST_BATCH_BYTES`) when it
opens. This runs one program (`batch_probe.c`) both ways and reads the batches off the wire through a relay
of its own, the same way for both:

    batch_control.py reference --out DIR [--sizes 512,2048,8192]
        zenoh-pico built as the same build as wz-capi-pico with `config-document`, once per size with
        BATCH_UNICAST_SIZE set to it (`capability_cost_gate.pico_reference_tree`, its switches from
        `wz_config.pico_reference`): each library copied to DIR/lib-P<size>, its headers to
        DIR/include-P<size>, and DIR/reference.json, which names each build
    batch_control.py run --bin-dir DIR --lib-dir DIR --run DIR [--sizes 512,2048,8192] [--count 1200]
        for each size, a subscriber that listens and a publisher that dials it through the relay, both
        processes of one build: arm P, the program built against the zenoh-pico of that size, and arm W,
        the program built once against libwz_capi_pico and handed the size at run time (`-B`). Writes
        DIR/batch.json and DIR/report.txt (DIR being --run); exit 0 when every cell held, 1 when a cell
        did not, 2 when a cell could not be measured
    batch_control.py --selftest
        the frame reader and the verdict on synthetic bytes

A cell HOLDS when its subscriber heard every sample, the publisher's InitSyn advertised the size, no
batch the publisher sent was longer than the size (its two length bytes counted, as both libraries
count them), and the largest was within ONE_MESSAGE_AT_MOST of it: inside a batching window a batch
leaves when the next message does not fit, so a burst of small samples fills each to within one
message.

Besides the cells, the run states what each size cost: the libraries each arm linked, told apart by
their digests. Arm P links one library per size, each from a CMake tree of its own; arm W links one.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import pathlib
import shutil
import socket
import subprocess
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

SCHEMA = "wz-pico-batch/1"
DEFAULT_SIZES = (512, 2048, 8192)
DEFAULT_COUNT = 1200
#: The wz features the program's library is built with beyond the default ones: the document door.
WZ_FEATURES = ("config-document",)
#: The bytes a stream link writes before each batch, which the batch size counts.
LENGTH_BYTES = 2
#: How far below its size the largest batch of a burst may stay: less than one message is left
#: unused, and a message of the burst (a short key and a fifteen-byte payload) is well inside this.
ONE_MESSAGE_AT_MOST = 128
#: zenoh's INIT message id (the low five bits of the header), its InitAck flag, and the flag that
#: says the resolutions and the batch size follow the zid.
MID_INIT = 0x01
FLAG_ACK = 0x20
FLAG_SIZE = 0x40
#: The batch size an InitSyn without the size flag stands for: zenoh's protocol default.
PROTOCOL_DEFAULT_BATCH = 65535
#: The seconds a subscriber is given to say it is ready, and a cell to end.
READY_S = 20
CELL_S = 90


def init_syn_batch(batch: bytes) -> int | None:
    """The batch size an InitSyn advertises, or None for a batch that is not an InitSyn. zenoh's layout:
    a header byte `|Z|S|A| INIT`, the version, a byte whose high nibble is the zid's length less one, the
    zid, and, when S is set, the resolutions and the batch size as two little-endian bytes."""
    if not batch:
        return None
    header = batch[0]
    if header & 0x1F != MID_INIT or header & FLAG_ACK:
        return None
    if not header & FLAG_SIZE:
        return PROTOCOL_DEFAULT_BATCH
    if len(batch) < 3:
        return None
    at = 3 + (batch[2] >> 4) + 1 + 1
    if len(batch) < at + 2:
        return None
    return int.from_bytes(batch[at:at + 2], "little")


class FrameReader:
    """The stream link's framing read back from the bytes of one connection as they pass: each batch
    behind its two little-endian length bytes. The first batch of a connection is the InitSyn."""

    def __init__(self) -> None:
        self.pending = bytearray()
        self.batches: list[int] = []
        self.advertised: int | None = None
        self.first = True

    def feed(self, data: bytes) -> None:
        self.pending += data
        while len(self.pending) >= LENGTH_BYTES:
            whole = LENGTH_BYTES + int.from_bytes(self.pending[:LENGTH_BYTES], "little")
            if len(self.pending) < whole:
                return
            if self.first:
                self.first = False
                self.advertised = init_syn_batch(bytes(self.pending[LENGTH_BYTES:whole]))
            self.batches.append(whole)
            del self.pending[:whole]


class Relay:
    """A listener on a port of its own that carries each connection to `upstream`, reading the framing of
    what the dialling side sends."""

    def __init__(self, upstream: int) -> None:
        self.upstream = upstream
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.server.settimeout(0.1)
        self.port = self.server.getsockname()[1]
        self.readers: list[FrameReader] = []
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self) -> None:
        while not self.stopping.is_set():
            try:
                dialler, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                upstream = socket.create_connection(("127.0.0.1", self.upstream), timeout=5)
            except OSError:
                dialler.close()
                continue
            dialler.settimeout(None)
            upstream.settimeout(None)
            reader = FrameReader()
            with self.lock:
                self.readers.append(reader)
            threading.Thread(target=self._pump, args=(dialler, upstream, reader), daemon=True).start()
            threading.Thread(target=self._pump, args=(upstream, dialler, None), daemon=True).start()

    def _pump(self, source: socket.socket, sink: socket.socket, reader: FrameReader | None) -> None:
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                if reader is not None:
                    with self.lock:
                        reader.feed(data)
                sink.sendall(data)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                sink.shutdown(socket.SHUT_WR)

    def seen(self) -> tuple[list[int], int | None]:
        """Every batch the dialling side sent, in order, and what the InitSyn of its last connection
        advertised."""
        with self.lock:
            batches = [size for reader in self.readers for size in reader.batches]
            advertised = self.readers[-1].advertised if self.readers else None
        return batches, advertised

    def close(self) -> None:
        self.stopping.set()
        self.thread.join(timeout=2)
        self.server.close()


def judge(size: int, batches: list[int], advertised: int | None, heard_all: bool) -> list[str]:
    """Why a cell of `size` did not hold; empty when it held."""
    why = []
    if not heard_all:
        why.append("the subscriber did not hear every sample")
    if advertised != size:
        why.append(f"the InitSyn advertised {advertised}, not {size}")
    over = [bytes_ for bytes_ in batches if bytes_ > size]
    if over:
        why.append(f"{len(over)} batch(es) past {size} bytes, the longest {max(over)}")
    largest = max(batches, default=0)
    if largest + ONE_MESSAGE_AT_MOST < size:
        why.append(f"no batch within one message of {size} bytes (the largest {largest})")
    return why


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Lines:
    """A process's output read on a thread of its own, so its pipe never fills, with a wait for a line."""

    def __init__(self, process: subprocess.Popen) -> None:
        self.lines: list[str] = []
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._read, args=(process,), daemon=True)
        self.thread.start()

    def _read(self, process: subprocess.Popen) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            self.lines.append(line.rstrip("\n"))
            if line.strip().endswith("ready"):
                self.ready.set()

    def text(self) -> str:
        self.thread.join(timeout=2)
        return "\n".join(self.lines) + "\n"


def run_cell(binary: pathlib.Path, arm: str, size: int, count: int, run: pathlib.Path) -> dict:
    """One size on one arm: a subscriber, a relay and a publisher, and what the relay read."""
    cell: dict = {"arm": arm, "size": size, "count": count, "status": "lost"}
    if not binary.is_file():
        cell["why"] = f"no program at {binary}"
        return cell
    stated = ["-B", str(size)] if arm == "W" else []
    port = free_port()
    sub = subprocess.Popen([str(binary), "sub", "-l", f"tcp/127.0.0.1:{port}", "-n", str(count), *stated],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    sub_lines = Lines(sub)
    relay = None
    try:
        if not sub_lines.ready.wait(READY_S):
            cell["why"] = f"the subscriber did not say ready in {READY_S} s"
            return cell
        relay = Relay(port)
        try:
            pub = subprocess.run([str(binary), "pub", "-e", f"tcp/127.0.0.1:{relay.port}", "-n", str(count),
                                  *stated], capture_output=True, text=True, timeout=CELL_S)
            sub_rc = sub.wait(timeout=CELL_S)
        except subprocess.TimeoutExpired as late:
            cell["why"] = f"{' '.join(map(str, late.cmd))} did not end in {late.timeout} s"
            return cell
        (run / f"{arm}-{size}-pub.txt").write_text(pub.stdout + pub.stderr, encoding="utf-8")
        batches, advertised = relay.seen()
        cell.update({"status": "measured", "pub_rc": pub.returncode, "sub_rc": sub_rc,
                     "advertised": advertised, "batches": len(batches),
                     "largest": max(batches, default=0), "over": sum(1 for b in batches if b > size)})
        if pub.returncode != 0:
            cell["status"] = "lost"
            cell["why"] = f"the publisher exited {pub.returncode}"
            return cell
        cell["failed"] = judge(size, batches, advertised, sub_rc == 0)
        return cell
    finally:
        if sub.poll() is None:
            sub.kill()
            sub.wait()
        (run / f"{arm}-{size}-sub.txt").write_text(sub_lines.text(), encoding="utf-8")
        if relay is not None:
            relay.close()


def sha256_of(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_sizes(text: str) -> list[int]:
    sizes = [int(word) for word in text.split(",") if word]
    if not sizes or any(not 1 <= size <= 65535 for size in sizes):
        raise ValueError(f"sizes are whole numbers from 1 to 65535, not {text!r}")
    return sizes


def cmd_reference(out: pathlib.Path, sizes: list[int]) -> int:
    """zenoh-pico built as the same build as wz-capi-pico with the document door, once per size."""
    # The gate's builder and resolver, imported here and not at the top: the selftest needs neither.
    import capability_cost_gate as cost
    import wz_config

    table = wz_config.manifest_features(cost.CRATES / "wz-capi-pico" / "Cargo.toml")
    features = wz_config.pico_build_features("tokio", list(WZ_FEATURES), table)
    asked = wz_config.pico_reference(wz_config.load_decl(), features)
    builds = []
    pin = toolchain = ""
    for size in sizes:
        switches = {**asked, "BATCH_UNICAST_SIZE": size}
        work, pin, toolchain = cost.pico_reference_tree(switches)
        header = (work / "build" / "include" / "zenoh-pico" / "config.h").read_text(encoding="utf-8")
        if f"#define Z_BATCH_UNICAST_SIZE {size}\n" not in header:
            print(f"batch-control: NOT-MEASURED, the zenoh-pico of {work} does not state a batch of {size}",
                  flush=True)
            return 2
        lib = out / f"lib-P{size}"
        inc = out / f"include-P{size}"
        for stale in (lib, inc):
            if stale.exists():
                shutil.rmtree(stale)
        lib.mkdir(parents=True)
        libraries = sorted((work / "build" / "lib").glob("libzenohpico.so*"))
        if not libraries:
            print(f"batch-control: NOT-MEASURED, no libzenohpico.so under {work / 'build' / 'lib'}", flush=True)
            return 2
        for path in libraries:
            shutil.copy2(path, lib / path.name, follow_symlinks=False)
        # pico's headers are its source tree's, with the config.h its CMake generated for this build on top.
        shutil.copytree(work / "src" / "include", inc, symlinks=True)
        shutil.copytree(work / "build" / "include", inc, dirs_exist_ok=True)
        builds.append({"size": size, "tree": str(work),
                       "refused": list(cost.refused_switches(switches, header))})
    record = {"pin": pin, "toolchain": toolchain, "switches": asked, "wz_features": sorted(features),
              "builds": builds}
    (out / "reference.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"batch-control: zenoh-pico {pin[:12]} built {len(builds)} times, once per size "
          f"({', '.join(map(str, sizes))}; {toolchain})", flush=True)
    return 0


def libraries_of(lib_dir: pathlib.Path, sizes: list[int]) -> dict:
    """The library each arm linked for each size, by digest: what a size cost in builds."""
    arms: dict = {"P": {}, "W": {}}
    for size in sizes:
        arms["P"][str(size)] = sha256_of(lib_dir / f"lib-P{size}" / "libzenohpico.so")
        arms["W"][str(size)] = sha256_of(lib_dir / "lib-W" / "libwz_capi_pico.so")
    return {arm: {"by_size": by_size, "distinct": len(set(by_size.values()))} for arm, by_size in arms.items()}


def report_lines(cells: list[dict], libraries: dict) -> list[str]:
    lines = ["arm size  status    advertised batches largest over  verdict"]
    for cell in cells:
        if cell["status"] != "measured":
            lines.append(f"{cell['arm']:<3} {cell['size']:<5} lost      {cell.get('why', '')}")
            continue
        verdict = "held" if not cell["failed"] else "FAILED: " + "; ".join(cell["failed"])
        lines.append(f"{cell['arm']:<3} {cell['size']:<5} measured  {str(cell['advertised']):<10} "
                     f"{cell['batches']:<7} {cell['largest']:<7} {cell['over']:<5} {verdict}")
    for arm, name in (("P", "zenoh-pico"), ("W", "wz")):
        lines.append(f"{name}: {libraries[arm]['distinct']} distinct librar"
                     f"{'y' if libraries[arm]['distinct'] == 1 else 'ies'} for "
                     f"{len(libraries[arm]['by_size'])} size(s)")
    return lines


def cmd_run(args: argparse.Namespace) -> int:
    try:
        sizes = parse_sizes(args.sizes)
    except ValueError as why:
        print(f"batch-control: {why}", file=sys.stderr)
        return 2
    bin_dir = pathlib.Path(args.bin_dir)
    run = pathlib.Path(args.run)
    run.mkdir(parents=True, exist_ok=True)
    cells = []
    for size in sizes:
        cells.append(run_cell(bin_dir / f"batch_probe_P{size}", "P", size, args.count, run))
        cells.append(run_cell(bin_dir / "batch_probe_W", "W", size, args.count, run))
    libraries = libraries_of(pathlib.Path(args.lib_dir), sizes)
    doc = {"schema": SCHEMA, "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "one_message_at_most": ONE_MESSAGE_AT_MOST, "cells": cells, "libraries": libraries}
    (run / "batch.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    lines = report_lines(cells, libraries)
    (run / "report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines), flush=True)
    if any(cell["status"] != "measured" for cell in cells):
        print(f"batch-control: NOT-MEASURED, a cell was lost; {run}", flush=True)
        return 2
    if any(cell["failed"] for cell in cells):
        print(f"batch-control: FAIL; {run}", flush=True)
        return 1
    print(f"batch-control: every cell held; {run}", flush=True)
    return 0


def synthetic_init_syn(batch: int, sized: bool = True) -> bytes:
    """An InitSyn with a zid of four bytes, advertising `batch` when `sized`."""
    header = MID_INIT | (FLAG_SIZE if sized else 0)
    body = bytes([header, 0x09, (4 - 1) << 4]) + b"\x01\x02\x03\x04"
    if sized:
        body += bytes([0x0A]) + batch.to_bytes(2, "little")
    return body


def framed(*batches: bytes) -> bytes:
    return b"".join(len(batch).to_bytes(2, "little") + batch for batch in batches)


def cmd_selftest() -> int:
    ok = bad = 0

    def expect(what: str, held: bool) -> None:
        nonlocal ok, bad
        if held:
            ok += 1
        else:
            bad += 1
            print(f"  batch-control selftest: FAIL {what}")

    expect("an InitSyn advertising 512 reads 512", init_syn_batch(synthetic_init_syn(512)) == 512)
    expect("an InitSyn without the size flag reads the protocol default",
           init_syn_batch(synthetic_init_syn(0, sized=False)) == PROTOCOL_DEFAULT_BATCH)
    expect("an InitAck is no InitSyn", init_syn_batch(bytes([MID_INIT | FLAG_ACK | FLAG_SIZE, 0x09])) is None)
    expect("a frame is no InitSyn", init_syn_batch(bytes([0x05, 0x00])) is None)
    expect("a cut InitSyn reads nothing", init_syn_batch(synthetic_init_syn(512)[:6]) is None)

    stream = framed(synthetic_init_syn(2048), b"\x05" * 100, b"\x05" * 2000)
    reader = FrameReader()
    for at in range(0, len(stream), 7):
        reader.feed(stream[at:at + 7])
    expect("batches split across reads are read whole, their length bytes counted",
           reader.batches == [2 + len(synthetic_init_syn(2048)), 102, 2002])
    expect("the first batch's InitSyn is what the connection advertised", reader.advertised == 2048)
    expect("nothing is left over", not reader.pending)
    late = FrameReader()
    late.feed(framed(b"\x05" * 10, synthetic_init_syn(512)))
    expect("an InitSyn after the first batch is not read as one", late.advertised is None)

    expect("a full burst under the size holds", judge(512, [40, 500, 510, 300], 512, True) == [])
    expect("a batch past the size fails", any("past 512" in why for why in judge(512, [513], 512, True)))
    expect("a burst that never fills fails",
           any("within one message" in why for why in judge(2048, [500, 600], 2048, True)))
    expect("another advertisement fails", any("advertised" in why for why in judge(512, [500], 2048, True)))
    expect("an unheard sample fails", any("every sample" in why for why in judge(512, [500], 512, False)))
    expect("sizes are read and held to the two bytes", parse_sizes("512,2048") == [512, 2048])
    for refused in ("", "0", "65536"):
        try:
            parse_sizes(refused)
        except ValueError:
            expect(f"the sizes {refused!r} are refused", True)
        else:
            expect(f"the sizes {refused!r} are refused", False)
    print(f"  batch-control selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return cmd_selftest()
    if len(argv) >= 2 and argv[1] == "reference":
        parser = argparse.ArgumentParser(prog="batch_control.py reference")
        parser.add_argument("--out", required=True)
        parser.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)))
        args = parser.parse_args(argv[2:])
        try:
            sizes = parse_sizes(args.sizes)
        except ValueError as why:
            print(f"batch-control: {why}", file=sys.stderr)
            return 2
        out = pathlib.Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        return cmd_reference(out, sizes)
    if len(argv) >= 2 and argv[1] == "run":
        parser = argparse.ArgumentParser(prog="batch_control.py run")
        parser.add_argument("--bin-dir", required=True)
        parser.add_argument("--lib-dir", required=True)
        parser.add_argument("--run", required=True)
        parser.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)))
        parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
        return cmd_run(parser.parse_args(argv[2:]))
    print(__doc__, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
