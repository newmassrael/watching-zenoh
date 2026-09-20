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
# one moves whenever `sources/network/session_rx_pool_ap.scxml` does.
#
# R2746 — the pool this reads MOVED, from `reassembly_pool_ap` to
# `session_rx_pool_ap`, because the adapter's registration did. This file's own
# rule is why the edit is required rather than optional: it reads the dims from
# the generated pool precisely so the number cannot drift from what gets
# registered, and after the repoint it was reading a pool the adapter no longer
# touches — the drift it exists to prevent, in its own subject.
# MEASURED, and the direction matters for a host near its limit: the requirement
# FALLS from 32 x 1 MiB to 64 x 65600, about 33.5 MB to about 4.2 MB. A box that
# was told it could not run this lane may now be able to.
#
# `$1` is the repo root, because the two callers stand in different directories.
uring_memlock_dims() {
    local root="$1"
    python3 - "$root" <<'PY'
import re, sys
root = sys.argv[1]
path = "%s/out/wz-runtime-tokio/session_rx_pool_ap.rs" % root
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
    # ⚠ R2755 -- THE GUARD USED TO READ `(( soft < need ))` AND THAT CONTRADICTED
    # THE PARAGRAPH BELOW IT. `need` is ONE registration's worth; the raise
    # exists for the MANY-registration case the comment goes on to describe. So
    # on any host whose ceiling admits one registration and not two, the
    # condition was false and the body -- the only thing that would have made
    # the lane runnable -- never ran. MEASURED: hosted run 35488108252 printed
    # `RLIMIT_MEMLOCK after raising: soft=8388608 hard=8388608` against a `need`
    # of 4464640, i.e. "after raising" with no raise attempted, and both of that
    # run's red jobs are registrations refused at that ceiling. The question
    # worth asking here is not whether the ceiling admits one registration --
    # the probe below answers that -- it is whether this process may have more,
    # and the answer is yes whenever the ceiling is not already unlimited.
    if [[ "$soft" != "-1" ]] && sudo -n true 2>/dev/null; then
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
        ulimit -l unlimited 2>/dev/null || true
        # RAISE ONLY. Now that the branch is reached with a ceiling that may
        # already exceed `need`, the old unconditional fallback would LOWER it
        # -- `ulimit -l` takes any value the process may set, downward included,
        # and a provisioning step that shrinks the ceiling it was called to
        # widen is worse than one that does nothing.
        soft="$(uring_soft_memlock_bytes)"
        if [[ "$soft" != "-1" ]] && (( soft < need )); then
            ulimit -l "$(( (need + 1023) / 1024 ))" 2>/dev/null || true
        fi
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
    local root="$1" count size need pages_per_slot page rc soft hard
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
    # C1br did, and the kernel refused at exactly the limit.
    #
    # ⚠ R2755 -- THE HEADROOM WAS ADDED TO THE WRONG QUANTITY. This read
    # `pool_bytes + count * page + page`, which adds one page per region to the
    # TOTAL; the charge is per-region rounding, so the floor is already
    # `count * ceil(size / page)` pages before any straddle. For 64 x 65600 on a
    # 4 KiB page that floor is 1088 pages and the old expression yielded 1090 --
    # over the floor by two pages and under the 1152-page worst case always.
    # MEASURED: a witness provisioned at the old number passed standalone and
    # was refused inside Layer C1br minutes later, same tree, on nothing but
    # where the pool's storage landed. The quantity to round is the SLOT.
    page="$(getconf PAGESIZE 2>/dev/null || echo 4096)"
    pages_per_slot=$(( (size + page - 1) / page + 1 ))
    need=$(( count * pages_per_slot * page ))

    uring_raise_memlock "$need"
    soft="$(uring_soft_memlock_bytes)"
    hard="$(uring_hard_memlock_bytes)"

    # The probe registers the SAME SHAPE the adapter does -- `count` separate
    # regions of `size`, not one big one -- because the page-straddle above is a
    # property of the shape. A single-region probe would pass while the real
    # registration of the same total failed.
    #
    # ⚠ R2755 -- AND IT NOW REGISTERS TWICE, because ONCE was not the lane's
    # shape either. Every caller runs a test BINARY that builds a ring per test;
    # a probe that registers once and exits reports "ready" for a capability the
    # lane does not have, which is exactly what hosted run 35488108252 printed
    # ("io_uring can register 64x65600 locked bytes") in the same job whose
    # registering tests then failed with ENOMEM. The second pass is preceded by
    # the probe's own `UNREGISTER_BUFFERS` opcode and a close, mirroring
    # `impl Drop for FixedSlotRing`: the property being measured is that the ceiling is whole
    # again before the next registration begins, which is the adapter's promise
    # and not the kernel's.
    #
    # What this probe does NOT measure, said so it is not read as covered: two
    # registrations LIVE AT ONCE, which `nondefault-tests-gate.sh`'s wide leg
    # can produce because it does not serialize. That needs twice the ceiling
    # and is what the `unlimited` raise above is for.
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
IORING_SETUP, IORING_REGISTER = 425, 427
REGISTER_BUFFERS, UNREGISTER_BUFFERS = 0, 1
bufs = [ctypes.create_string_buffer(size) for _ in range(count)]
iovs = (IoVec * count)(*[IoVec(ctypes.cast(b, ctypes.c_void_p), size) for b in bufs])

def one_pass():
    """Set up a ring, register the pool, release it the way the adapter does.

    Returns 0 ready / 2 no io_uring / 3 ENOMEM / 4 some other errno."""
    p = P()
    fd = libc.syscall(IORING_SETUP, 8, ctypes.byref(p))
    if fd < 0:
        return 2
    try:
        rc = libc.syscall(IORING_REGISTER, fd, REGISTER_BUFFERS,
                          ctypes.byref(iovs), count)
        if rc < 0:
            err = ctypes.get_errno()
            return 3 if err == 12 else 4
        # The release `impl Drop for FixedSlotRing` performs. Without it the
        # close below leaves the charge to the kernel's deferred teardown and
        # the SECOND pass measures that instead.
        libc.syscall(IORING_REGISTER, fd, UNREGISTER_BUFFERS, None, 0)
        return 0
    finally:
        os.close(fd)

rc = one_pass()
if rc == 0:
    rc = one_pass()
sys.exit(rc)
PY
    rc=$?
    case "$rc" in
        0) URING_MEMLOCK_WHY="io_uring can register ${count}x${size} locked bytes TWICE IN A ROW (RLIMIT_MEMLOCK after raising: soft=${soft} hard=${hard} bytes, -1 = unlimited)" ;;
        2) URING_MEMLOCK_WHY="io_uring_setup refused by this kernel" ;;
        3) URING_MEMLOCK_WHY="io_uring_register refused ${count}x${size} locked bytes with ENOMEM on one of two consecutive passes (needed ${need} incl. page headroom; RLIMIT_MEMLOCK after raising: soft=${soft} hard=${hard} bytes, -1 = unlimited)" ;;
        *) URING_MEMLOCK_WHY="the io_uring capability probe failed with an errno that is NOT ENOMEM (rc=${rc}) -- that is a defect, not provisioning" ;;
    esac
    return $rc
}

# ─── selftest ───────────────────────────────────────────────────────
#
# R2755. `uring_raise_memlock`'s privileged branch runs only where passwordless
# sudo exists, which on every developer box in this tree is nowhere -- so the
# branch hosted CI depends on was, until this round, reachable by no local run
# at all. A branch nothing can execute cannot be told apart from a branch that
# is correct, and the guard on this one was wrong for two rounds under exactly
# that cover. Same objection `ident-gate.sh` states for its pre-push-only core,
# answered the same way.
#
# The arms below drive it against a STUB `sudo` on PATH which records its argv,
# so what is graded is the DECISION -- did this function ask for a bigger
# ceiling -- and not whether the host would have granted it. That is the half
# that was defective; granting is the kernel's.
#
# Run: bash scripts/lib/uring-memlock.sh --selftest
#
# shellcheck disable=SC2030,SC2031  # each arm runs `uring_raise_memlock` inside
# a `$( )` so the stub PATH and the log path are scoped to that one call. The
# locality shellcheck is warning about is the point: an arm must not inherit the
# previous arm's environment, and the value each one needs is what it echoes.
wz_uring_memlock_selftest() {
    local tmp pass=0 fail=0 log
    tmp="$(mktemp -d)" || return 1
    log="$tmp/sudo.argv"

    # A `sudo` that says yes to `-n true`, records every other invocation, and
    # changes no limit. `prlimit` is deliberately NOT performed: this grades the
    # ask, and performing it would need the privilege the stub stands in for.
    # shellcheck disable=SC2016  # these lines are the STUB's source, not this
    # script's: `$1` and `$*` must reach the stub unexpanded.
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'if [ "$1" = "-n" ] && [ "$2" = "true" ]; then exit 0; fi' \
        'printf "%s\n" "$*" >> "${WZ_URING_SELFTEST_LOG}"' \
        'exit 0' > "$tmp/sudo"
    chmod +x "$tmp/sudo"

    _t() { # name, expected, actual
        if [ "$2" = "$3" ]; then
            echo "  ok    $1"
            pass=$((pass + 1))
        else
            echo "  FAIL  $1  want '$2', got '$3'"
            fail=$((fail + 1))
        fi
    }

    # -- arm 1 -- the ceiling ALREADY admits one registration, and the raise
    # must still be asked for. This is hosted run 35488108252's exact shape:
    # `soft` at 8388608 against a `need` of 4464640. Before R2755 the guard read
    # `(( soft < need ))` and this arm records nothing.
    local asked
    asked="$(
        export WZ_URING_SELFTEST_LOG="$log" PATH="$tmp:$PATH"
        : > "$log"
        uring_raise_memlock 1024 >/dev/null 2>&1
        command grep -c -- '--memlock=unlimited:unlimited' "$log"
    )"
    _t "a ceiling that admits one registration still asks for more" 1 "$asked"

    # -- arm 2 -- and it asks for UNLIMITED first, not for `need`. Provisioning
    # exactly one registration's worth is the shape this file's header records
    # as having produced a second failure.
    local first
    first="$(
        export WZ_URING_SELFTEST_LOG="$log" PATH="$tmp:$PATH"
        : > "$log"
        uring_raise_memlock 1024 >/dev/null 2>&1
        head -n 1 "$log" | command grep -o -- '--memlock=[^ ]*'
    )"
    _t "the first ask is for unlimited" "--memlock=unlimited:unlimited" "$first"

    # -- arm 3 -- and it never LOWERS the ceiling. With the guard gone, the
    # fallback `ulimit -l "$need"` is reached with a soft limit that may already
    # exceed `need`, where it would shrink what it was called to widen.
    local before after
    before="$(uring_soft_memlock_bytes)"
    after="$(
        export WZ_URING_SELFTEST_LOG="$log" PATH="$tmp:$PATH"
        uring_raise_memlock 1024 >/dev/null 2>&1
        uring_soft_memlock_bytes
    )"
    if [ "$before" = "-1" ] || [ "$after" = "-1" ] || (( after >= before )); then
        echo "  ok    the raise never lowers the ceiling  (${before} -> ${after})"
        pass=$((pass + 1))
    else
        echo "  FAIL  the raise LOWERED the ceiling: ${before} -> ${after}"
        fail=$((fail + 1))
    fi

    # -- arm 4 -- the requirement is READ from the generated pool. A literal
    # here would be the same fact in two places, which is this file's own stated
    # reason for parsing it.
    local root dims
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    dims="$(uring_memlock_dims "$root" 2>/dev/null)"
    if [[ "$dims" =~ ^[0-9]+\ [0-9]+$ ]]; then
        echo "  ok    the dims come from the generated pool  (${dims})"
        pass=$((pass + 1))
    else
        echo "  FAIL  the generated pool did not yield dims: '${dims}'"
        fail=$((fail + 1))
    fi

    rm -rf "$tmp"
    echo "uring-memlock selftest: $((pass))/$((pass + fail)) arm(s) pass"
    [ "$fail" -eq 0 ]
}

if [ "${1:-}" = "--selftest" ]; then
    wz_uring_memlock_selftest
    exit $?
fi
