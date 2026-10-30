#!/usr/bin/env bash
# R2575 (no register item) — a SEPARATE network stack for a witness, as a
# reusable topology. The citation is `no register item` because what this
# answers is the owner's decision of 2026-09-12 to GROW THE ENVIRONMENT for
# oracle-blocked atoms rather than grade their residuals out; that decision has
# no store `debt-` id for `gate_provenance_lint` to resolve, so naming it in
# prose here is the honest pair. (Added R2576: the header was written without
# one and hosted Layer C0 would have said so a round later.)
#
# ## Why this exists
#
# Four atoms in the REMAINING set are held open not by missing code but by a
# missing ORACLE: their claim needs a party this host cannot provide. The
# owner's decision (2026-09-12) was to GROW THE ENVIRONMENT rather than grade
# those residuals out, and this file is the cheap half of that.
#
# It gives a caller a second network stack: a named netns joined to this one by
# a veth pair, each end addressed. That is what a witness needs when the claim
# is about SEPARATION -- a peer whose link can be severed independently, a
# foreign implementation driven in a role wz cannot drive on loopback.
#
# ## ⛔ What it is NOT, measured rather than assumed
#
# It does NOT give a routed HOP, so it cannot witness anything that counts
# hops -- multicast TTL above all. MEASURED on this tree before this file was
# written: with two namespaces joined by a veth pair, a datagram sent at
# `IP_MULTICAST_TTL = 1` and one sent at `8` BOTH arrived. TTL counts router
# hops and a veth pair is one L2 link inside one subnet, so this topology fails
# to discriminate TTL for exactly the reason loopback does.
#
# A ttl witness that asserts DELIVERY on this substrate would therefore pass for
# EVERY ttl value, which is the "population of zero reports green" shape this
# tree has paid for more than once. Witnessing REACH needs a real
# multicast-routing hop -- a third namespace with the kernel's MFC populated by
# an `smcroute` / `pimd` class daemon -- which is a new dependency and a
# separate decision.
#
# R2587 — but reach is not what a `ttl` config key controls. The key sets the
# value the implementation writes into the IP header, and one link does not
# decrement it, so a receiver here reads it unchanged through `IP_RECVTTL`.
# Measured: zenohd told `ttl=5` arrived as 5 and without the key as 1.
# `wz_multicast_ttl_on_the_wire_netns_zenohd_interop` holds wz to the same values
# with zenohd as the adjudicator. Do not read that as covering reach, and do not
# read this paragraph's first half as ruling out the header witness.
#
# ## Verdict policy belongs to the CALLER
#
# Same split as `uring-memlock.sh`: this file reports FACTS through exit codes
# and `NETNS_TOPOLOGY_WHY`, and the lane decides whether an absence is a SKIP
# or a FAIL. The codes keep "this host cannot" apart from "this host can and it
# broke", because only the first is ever a legitimate skip:
#
#   0 — available (probe) / built (up)
#   3 — probe only: not with the privilege this process holds, but inside the
#       sandbox (`netns_sandbox_exec`): the lane wraps its witness in
#       `scripts/lib/netns-sandbox.sh`
#   2 — PROVISIONING absence: no `ip`, or neither non-interactive sudo nor a
#       sandbox. Skippable.
#   4 — a DEFECT: the tools are here, the attempt ran, and it failed. Never a
#       skip, anywhere, because something that used to work has stopped.
#
# The probe is a REAL construction, not a capability guess -- it builds a
# throwaway namespace and deletes it. `uring-memlock.sh`'s own comment makes
# that argument for io_uring ("a real io_uring_setup rather than a kernel
# version compare"), and a sysctl read would be exactly the guess it warns
# about: this host permits userns by kernel knob
# (`kernel.unprivileged_userns_clone=1`) while AppArmor refuses it anyway
# (`apparmor_restrict_unprivileged_userns=1`), so the knob and the truth
# disagree here TODAY.

# shellcheck shell=bash

NETNS_TOPOLOGY_WHY=""

# Names are bounded by the kernel's IFNAMSIZ (15 usable chars), so a caller's
# tag is truncated rather than silently producing an `ip` error that reads as a
# defect.
_netns_ifname() {
    printf 'wz%.11s' "$1"
}

# ## Two ways to hold the privilege a namespace needs
#
# A namespace takes CAP_NET_ADMIN, and a host gives it in one of two ways:
#
#   * sudo -n -- the default. Namespaces are the HOST's, and the veth pair joins
#     the host's own stack to the new one.
#   * a sandbox -- `netns_sandbox_exec`: the command runs under `bwrap` in a
#     network namespace of its own, with the capabilities granted inside that
#     user namespace, and `WZ_NETNS_SANDBOX=1` says so. "This side" is then the
#     sandbox's stack, and the veth pair joins THAT to the new namespace. It
#     needs no sudo, which is what the build machines have: they carry the
#     AppArmor profile that lets bwrap own a user namespace (owner, 2026-10-28),
#     and the facility oracle's raw Ethernet runs already stand on it.
#
# `netns_priv` is the one place that decides which; every privileged `ip` call
# here and every Rust call (`NetnsPair`) goes through it, so the two cannot
# disagree about the privilege a topology was built with.
netns_priv() {
    if [[ "${WZ_NETNS_SANDBOX:-}" == 1 ]]; then
        "$@"
    else
        sudo -n "$@"
    fi
}

netns_topology_down() {
    local tag="$1" ns="wzns$1" host
    host="$(_netns_ifname "$tag")0"
    # Deleting the host end takes the peer with it; the netns delete is what
    # reclaims the name. Both are idempotent on purpose: teardown runs from a
    # trap, which fires whether or not `up` got that far.
    netns_priv ip link del "$host" 2>/dev/null
    netns_priv ip netns del "$ns" 2>/dev/null
    return 0
}

# netns_topology_up <tag> <host-cidr> <peer-cidr>
#
# Leaves a netns `wzns<tag>` reachable at <peer-cidr> from <host-cidr> on this
# side. The caller is responsible for `netns_topology_down <tag>`, and should
# arm it with a trap BEFORE calling this.
netns_topology_up() {
    local tag="$1" host_cidr="$2" peer_cidr="$3"
    local ns="wzns$1" host peer
    host="$(_netns_ifname "$tag")0"
    peer="$(_netns_ifname "$tag")1"

    if ! command -v ip >/dev/null 2>&1; then
        NETNS_TOPOLOGY_WHY="no \`ip\` on PATH (iproute2 absent)"
        return 2
    fi
    if [[ "${WZ_NETNS_SANDBOX:-}" != 1 ]] && ! sudo -n true 2>/dev/null; then
        NETNS_TOPOLOGY_WHY="no non-interactive sudo; a netns needs CAP_NET_ADMIN"
        return 2
    fi

    # From here the tools ARE present, so every failure below is a defect (4)
    # rather than an absence (2). That boundary is the whole point of the split.
    netns_topology_down "$tag"
    if ! netns_priv ip netns add "$ns" 2>/dev/null; then
        NETNS_TOPOLOGY_WHY="\`ip netns add $ns\` failed with the privilege available"
        return 4
    fi
    if ! netns_priv ip link add "$host" type veth peer name "$peer" netns "$ns" 2>/dev/null; then
        NETNS_TOPOLOGY_WHY="\`ip link add $host type veth\` failed"
        return 4
    fi
    if ! netns_priv ip addr add "$host_cidr" dev "$host" 2>/dev/null \
        || ! netns_priv ip link set "$host" up 2>/dev/null \
        || ! netns_priv ip netns exec "$ns" ip addr add "$peer_cidr" dev "$peer" 2>/dev/null \
        || ! netns_priv ip netns exec "$ns" ip link set "$peer" up 2>/dev/null \
        || ! netns_priv ip netns exec "$ns" ip link set lo up 2>/dev/null; then
        NETNS_TOPOLOGY_WHY="addressing $host/$peer failed after both links existed"
        return 4
    fi
    NETNS_TOPOLOGY_WHY=""
    return 0
}

# Run <command...> inside the sandbox, replacing this shell.
#
# The sandbox is `bwrap` with the host's files, a network namespace of its own
# and a user namespace that carries exactly the capabilities a topology needs:
#
#   CAP_NET_ADMIN  create and address a namespace and a veth pair
#   CAP_SYS_ADMIN  `ip netns add` bind-mounts the namespace under /run/netns
#   CAP_NET_RAW    `ping`, and a raw socket of a witness that wants one
#
# `/run` is a tmpfs of the sandbox's own, because `ip netns` writes
# /run/netns and a user's /run is not theirs to write. Its children are not
# lost: `bwrap` resolves a source path on the HOST, so `--bind /run/user` puts
# the host's /run/user back (the build machines keep their compiler cache
# socket there). MEASURED on a build machine (bwrap 0.9.0, which has no
# overlay option to do this with): the namespace, the veth pair, the addressing
# and a ping across it all work with no sudo, and the cache socket stays
# visible.
#
# A host has an interface its default route leaves by, and a witness may stand on
# that (the scout fan-out leg: a Scout on the default route must NOT reach a peer
# only the veth hears). A fresh network namespace has `lo` and nothing else, so
# the sandbox's first act is to give itself the host's shape: one multicast
# capable interface with an address and a default route (`--sandbox-init`).
netns_sandbox_exec() {
    exec bwrap --bind / / --dev-bind /dev /dev --proc /proc \
        --tmpfs /run --bind-try /run/user /run/user \
        --unshare-user --unshare-net \
        --cap-add CAP_NET_ADMIN --cap-add CAP_SYS_ADMIN --cap-add CAP_NET_RAW \
        --setenv WZ_NETNS_SANDBOX 1 -- bash "${BASH_SOURCE[0]}" --sandbox-init "$@"
}

# Inside the sandbox: an interface the default route leaves by, standing for the
# host's. Not every kernel offers a dummy device to a user namespace, and a
# witness that needs the route states that premise itself, so a refusal is said
# on stderr and the command still runs.
_netns_sandbox_host_side() {
    if ip link add wzhost0 type dummy 2>/dev/null \
        && ip link set wzhost0 multicast on 2>/dev/null \
        && ip addr add 10.250.255.1/24 dev wzhost0 2>/dev/null \
        && ip link set wzhost0 up 2>/dev/null \
        && ip route add default via 10.250.255.254 dev wzhost0 onlink 2>/dev/null; then
        return 0
    fi
    echo "netns sandbox: no default-route interface could be made; a witness that needs the host's default route will say so" >&2
    return 1
}

# Can this host build a topology in a sandbox? The same measurement as the
# direct probe, taken inside one: 0 = yes, 2 = no `bwrap`, or this host's policy
# does not let one make its namespaces (the AppArmor profile is a provisioning
# step, so its absence is a skip), 4 = the sandbox came up and the build broke.
netns_sandbox_probe() {
    if ! command -v bwrap >/dev/null 2>&1; then
        NETNS_TOPOLOGY_WHY="no \`bwrap\` on PATH"
        return 2
    fi
    if ! bwrap --bind / / --unshare-user --unshare-net -- true 2>/dev/null; then
        NETNS_TOPOLOGY_WHY="bwrap cannot make a user and network namespace here (no AppArmor profile for it?)"
        return 2
    fi
    local rc
    (netns_sandbox_exec bash "${BASH_SOURCE[0]}" --probe-inner) 2>/dev/null
    rc=$?
    if (( rc == 0 )); then
        NETNS_TOPOLOGY_WHY=""
        return 0
    fi
    NETNS_TOPOLOGY_WHY="a topology built inside bwrap failed (rc $rc)"
    return 4
}

# Can this host build one at all? Builds a throwaway and deletes it, so the
# answer is a measurement rather than a reading of a knob. Four answers, and the
# caller owns what each means:
#
#   0  built with the privilege this process already holds (sudo, or already
#      inside the sandbox): run the witness as it is
#   3  not that way, but inside the sandbox: run the witness under
#      `scripts/lib/netns-sandbox.sh`
#   2  neither: a provisioning absence
#   4  the tools are here and a build broke: a defect, never a skip
netns_topology_probe() {
    local rc
    netns_topology_up probe 10.253.0.1/30 10.253.0.2/30
    rc=$?
    netns_topology_down probe
    if (( rc != 2 )); then
        return $rc
    fi
    local direct_why="$NETNS_TOPOLOGY_WHY"
    netns_sandbox_probe
    rc=$?
    if (( rc == 0 )); then
        return 3
    fi
    NETNS_TOPOLOGY_WHY="$direct_why; $NETNS_TOPOLOGY_WHY"
    return $rc
}

# The first command inside the sandbox: give it a host's default route, then run
# what was asked.
if [[ "${BASH_SOURCE[0]}" == "${0}" && "${1:-}" == "--sandbox-init" ]]; then
    shift
    _netns_sandbox_host_side || true
    exec "$@"
fi

# The inner half of the sandbox probe: it runs INSIDE the sandbox, where the
# privilege is held, and builds and deletes the throwaway there.
if [[ "${BASH_SOURCE[0]}" == "${0}" && "${1:-}" == "--probe-inner" ]]; then
    netns_topology_probe_inner() {
        local rc
        netns_topology_up probe 10.253.0.1/30 10.253.0.2/30
        rc=$?
        netns_topology_down probe
        return $rc
    }
    netns_topology_probe_inner
    exit $?
fi

# The body of the selftest, in whichever place holds the privilege: the real
# construction, the REACHABILITY that makes it a topology rather than two
# unrelated interfaces, and the teardown leaving nothing behind.
_netns_selftest_body() {
    local rc
    trap 'netns_topology_down st' EXIT
    netns_topology_up st 10.252.0.1/30 10.252.0.2/30
    rc=$?
    if (( rc == 0 )); then
        if netns_priv ip netns exec wznsst ping -c1 -W2 10.252.0.1 >/dev/null 2>&1; then
            echo "  netns-topology selftest: built wznsst, peer reaches the host end"
        else
            echo "  netns-topology selftest FAIL: built, but the peer cannot reach 10.252.0.1" >&2
            return 1
        fi
        netns_topology_down st
        if netns_priv ip netns list 2>/dev/null | grep -q '^wznsst'; then
            echo "  netns-topology selftest FAIL: teardown left wznsst behind" >&2
            return 1
        fi
        echo "  netns-topology selftest: teardown left nothing behind"
        return 0
    fi
    if (( rc == 4 )); then
        echo "  netns-topology selftest FAIL: $NETNS_TOPOLOGY_WHY" >&2
        return 1
    fi
    echo "  netns-topology selftest SKIP: $NETNS_TOPOLOGY_WHY"
    return 0
}

# `bash netns-topology.sh --selftest` -- the body above, once with the host's
# own privilege when it has one, and once in the sandbox when that is available.
# A host with neither skips, and one whose build broke fails.
if [[ "${BASH_SOURCE[0]}" == "${0}" && "${1:-}" == "--selftest" ]]; then
    if [[ "${WZ_NETNS_SANDBOX:-}" == 1 ]]; then
        _netns_selftest_body
        exit $?
    fi
    netns_topology_probe
    case $? in
        0)
            _netns_selftest_body
            exit $?
            ;;
        3)
            echo "  netns-topology selftest: no sudo here, so inside the sandbox"
            netns_sandbox_exec bash "${BASH_SOURCE[0]}" --selftest
            ;;
        4)
            echo "  netns-topology selftest FAIL: $NETNS_TOPOLOGY_WHY" >&2
            exit 1
            ;;
        *)
            echo "  netns-topology selftest SKIP: $NETNS_TOPOLOGY_WHY"
            exit 0
            ;;
    esac
fi
