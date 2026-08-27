#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R2163 (no register item) — the `runtime-tokio-uring` PROVISIONING
# precondition, as one spelling with more than one caller.
#
# The citation reads `no register item` because what this closes is a HOSTED
# RED (runs 33059064203 / 33059199683), not a register entry: no open-debt item
# had named it, which is itself the measurement — the class was invisible until
# a second lane ran the same tests.
#
# ## The defect this exists to close, measured
#
# `FixedSlotRing::register` pins the whole reassembly pool, and pinned pages are
# charged to `RLIMIT_MEMLOCK`. The pool is 32 x 1 MiB, so any runner of
# `uring::tests::*` needs ~32 MiB of lockable memory. R311y593 established that
# and put the raising, the probe and the three-way verdict INSIDE Layer C1br.
#
# That made the requirement lane-local, and R2156 then added a second runner:
# `nondefault-tests-gate.sh`'s wide `wz-runtime-tokio` leg names
# `runtime-tokio-uring` among its features, so `--all-legs` runs the same two
# registering tests -- with none of C1br's provisioning. MEASURED on hosted run
# 33059064203, job `feature-gate NEG lanes`:
#
#   * Layer C1br, same job, same runner: `pass (41s)` -- it provisions first;
#   * Layer C1bn, same job, minutes later: `1318 passed; 2 failed`, both
#     `uring::tests::`, `RLIMIT_MEMLOCK is soft=8388608 hard=8388608 bytes`.
#
# Two lanes, one runner, opposite verdicts about the same two tests, and the
# difference is entirely which of them knew to raise the limit. Every dev box in
# this tree grants 3.9 GiB, so the asymmetry is structurally invisible locally --
# the same shape as R2136's, and the reason the knowledge had to move out of the
# lane rather than be copied into the second one.
#
# ## Contract
#
# Source this file, then call `uring_memlock_provision`. It raises the limit as
# far as this process may, then PROBES with a real
# `io_uring_register(IORING_REGISTER_BUFFERS)` of the adapter's own shape, and
# returns what the host can actually do:
#
#   0  ready -- the registration this feature needs will succeed
#   2  no io_uring on this kernel (provisioning fact)
#   3  ENOMEM: the limit is short and could not be raised (provisioning fact)
#   4  some OTHER errno -- a DEFECT, and never excusable as provisioning
#
# `URING_MEMLOCK_WHY` carries the sentence to print, with every number in it.
# Deciding what a non-zero return MEANS is the caller's -- C1br SKIPs 2 and 3
# locally and FAILs them hosted; each caller states its own policy.

# The requirement is READ from the generated pool, never written down here. The
# same fact reached by two paths always drifts (R311y589's own lesson), and this
# one moves whenever `sources/network/reassembly_pool_ap.scxml` does.
#
# `$1` is the repo root, because the two callers stand in different directories.
uring_memlock_dims() {
    local root="$1"
    python3 - "$root" <<'PY'
import re, sys
root = sys.argv[1]
path = "%s/out/wz-runtime-tokio/reassembly_pool_ap.rs" % root
try:
    src = open(path, encoding="utf-8").read()
except OSError as e:
    sys.exit("cannot read the generated pool at %s: %s" % (path, e))
def const(name):
    m = re.search(r"pub const %s: usize = (\d+);" % name, src)
    if not m:
        sys.exit("cannot read %s from the generated pool" % name)
    return int(m.group(1))
print(const("SLOT_COUNT"), const("SLOT_SIZE"))
PY
}

# `ulimit` speaks KIBIBYTES and the requirement is in BYTES. Converting at the
# one place that reads the limit -- the first version of this printed a soft
# limit in bytes beside a hard limit in KiB, in the same sentence.
_uring_memlock_bytes() {
    local s
    s="$(ulimit "$1")"
    if [[ "$s" == "unlimited" ]]; then echo "-1"; else echo "$(( s * 1024 ))"; fi
}
uring_soft_memlock_bytes() { _uring_memlock_bytes -Sl; }
uring_hard_memlock_bytes() { _uring_memlock_bytes -Hl; }

# Raise this shell's RLIMIT_MEMLOCK toward `$1` bytes, by the two routes an
# unprivileged process has. Best-effort throughout: every failure here is
# reported by the probe that follows, so a silent `|| true` cannot hide one.
uring_raise_memlock() {
    local need="$1" hard soft
    hard="$(ulimit -Hl)"
    if [[ "$hard" == "unlimited" ]]; then
        ulimit -l unlimited 2>/dev/null || true
    else
        ulimit -l "$hard" 2>/dev/null || true
    fi
    soft="$(uring_soft_memlock_bytes)"
    if [[ "$soft" != "-1" ]] && (( soft < need )) && sudo -n true 2>/dev/null; then
        # Raising the HARD limit needs privilege. A CI runner is precisely where
        # that is available, and `prlimit` on our own pid is the narrowest form
        # of it -- no test runs as root.
        #
        # UNLIMITED, not `need`. Provisioning exactly one registration's worth is
        # what the first version did, and it produced a second failure that took
        # a bisect to read: io_uring context teardown is DEFERRED, so a binary
        # that registers the pool in several tests still holds the earlier
        # charges when the next one registers, even run single-threaded. The
        # minimum is the PROBE's business; what a host should grant a lane that
        # pins memory is as much as it will.
        sudo -n prlimit --memlock=unlimited:unlimited --pid $$ 2>/dev/null \
            || sudo -n prlimit "--memlock=${need}:${need}" --pid $$ 2>/dev/null || true
        ulimit -l unlimited 2>/dev/null \
            || ulimit -l "$(( (need + 1023) / 1024 ))" 2>/dev/null || true
    fi
}

# Raise, then probe. `$1` is the repo root. Sets `URING_MEMLOCK_WHY` and returns
# 0 / 2 / 3 / 4 per the contract in the header.
#
# ⚠ The limit is a property of THIS PROCESS and its children, so a caller that
# provisions in one shell and runs cargo in another has provisioned nothing.
# Both callers run the tests from the same shell that calls this, and that is
# not incidental.
#
# shellcheck disable=SC2034  # URING_MEMLOCK_WHY is this file's OUTPUT: it is
# read by the two sourcing callers (run-ci.sh's C1br and
# nondefault-tests-gate.sh), which shellcheck cannot see from here. Returning it
# on stdout instead would collide with the probe's own output and force every
# caller to parse; a named variable beside a return code is the contract the
# header states.
uring_memlock_provision() {
    local root="$1" count size need pool_bytes page rc soft hard
    URING_MEMLOCK_WHY=""

    read -r count size < <(uring_memlock_dims "$root") || {
        URING_MEMLOCK_WHY="could not derive the locked-byte requirement from the generated pool"
        return 4
    }
    [[ -n "$count" && -n "$size" ]] || {
        URING_MEMLOCK_WHY="the generated pool's dims did not parse"
        return 4
    }

    # The kernel charges WHOLE PAGES per registered region, and the pool's slots
    # are not page-aligned, so each of the `count` regions can straddle one extra
    # page. Provisioning the bare pool size is what the first version of Layer
    # C1br did, and the kernel refused at exactly the limit. One page per region
    # plus one is the worst case, stated rather than fudged.
    pool_bytes=$(( count * size ))
    page="$(getconf PAGESIZE 2>/dev/null || echo 4096)"
    need=$(( pool_bytes + count * page + page ))

    uring_raise_memlock "$need"
    soft="$(uring_soft_memlock_bytes)"
    hard="$(uring_hard_memlock_bytes)"

    # The probe registers the SAME SHAPE the adapter does -- `count` separate
    # regions of `size`, not one big one -- because the page-straddle above is a
    # property of the shape. A single-region probe would pass while the real
    # registration of the same total failed.
    python3 - "$count" "$size" <<'PY'
import ctypes, os, sys
count, size = int(sys.argv[1]), int(sys.argv[2])
libc = ctypes.CDLL(None, use_errno=True)
class P(ctypes.Structure):
    _fields_ = [("sq_entries", ctypes.c_uint32), ("cq_entries", ctypes.c_uint32),
                ("flags", ctypes.c_uint32), ("sq_thread_cpu", ctypes.c_uint32),
                ("sq_thread_idle", ctypes.c_uint32), ("features", ctypes.c_uint32),
                ("wq_fd", ctypes.c_uint32), ("resv", ctypes.c_uint32 * 3),
                ("sq_off", ctypes.c_uint64 * 10), ("cq_off", ctypes.c_uint64 * 10)]
class IoVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]
p = P()
fd = libc.syscall(425, 8, ctypes.byref(p))        # io_uring_setup
if fd < 0:
    sys.exit(2)
bufs = [ctypes.create_string_buffer(size) for _ in range(count)]
iovs = (IoVec * count)(*[IoVec(ctypes.cast(b, ctypes.c_void_p), size) for b in bufs])
rc = libc.syscall(427, fd, 0, ctypes.byref(iovs), count)  # io_uring_register, BUFFERS
err = ctypes.get_errno()
os.close(fd)
sys.exit(0 if rc >= 0 else (3 if err == 12 else 4))
PY
    rc=$?
    case "$rc" in
        0) URING_MEMLOCK_WHY="io_uring can register ${count}x${size} locked bytes (RLIMIT_MEMLOCK after raising: soft=${soft} hard=${hard} bytes, -1 = unlimited)" ;;
        2) URING_MEMLOCK_WHY="io_uring_setup refused by this kernel" ;;
        3) URING_MEMLOCK_WHY="io_uring_register refused ${count}x${size} locked bytes with ENOMEM (needed ${need} incl. page headroom; RLIMIT_MEMLOCK after raising: soft=${soft} hard=${hard} bytes, -1 = unlimited)" ;;
        *) URING_MEMLOCK_WHY="the io_uring capability probe failed with an errno that is NOT ENOMEM (rc=${rc}) -- that is a defect, not provisioning" ;;
    esac
    return $rc
}
