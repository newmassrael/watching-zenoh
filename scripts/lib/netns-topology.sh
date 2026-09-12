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
# A ttl witness written on this substrate would therefore pass for EVERY ttl
# value, which is the "population of zero reports green" shape this tree has
# paid for more than once. Closing that clause needs a real multicast-routing
# hop -- a third namespace with the kernel's MFC populated by an `smcroute` /
# `pimd` class daemon -- which is a new dependency and a separate decision.
# Do not read "the environment grew" as covering it.
#
# ## Verdict policy belongs to the CALLER
#
# Same split as `uring-memlock.sh`: this file reports FACTS through exit codes
# and `NETNS_TOPOLOGY_WHY`, and the lane decides whether an absence is a SKIP
# or a FAIL. The codes keep "this host cannot" apart from "this host can and it
# broke", because only the first is ever a legitimate skip:
#
#   0 — available (probe) / built (up)
#   2 — PROVISIONING absence: no `ip`, or no non-interactive sudo. Skippable.
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

netns_topology_down() {
    local tag="$1" ns="wzns$1" host
    host="$(_netns_ifname "$tag")0"
    # Deleting the host end takes the peer with it; the netns delete is what
    # reclaims the name. Both are idempotent on purpose: teardown runs from a
    # trap, which fires whether or not `up` got that far.
    sudo -n ip link del "$host" 2>/dev/null
    sudo -n ip netns del "$ns" 2>/dev/null
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
    if ! sudo -n true 2>/dev/null; then
        NETNS_TOPOLOGY_WHY="no non-interactive sudo; a netns needs CAP_NET_ADMIN"
        return 2
    fi

    # From here the tools ARE present, so every failure below is a defect (4)
    # rather than an absence (2). That boundary is the whole point of the split.
    netns_topology_down "$tag"
    if ! sudo -n ip netns add "$ns" 2>/dev/null; then
        NETNS_TOPOLOGY_WHY="\`ip netns add $ns\` failed with sudo available"
        return 4
    fi
    if ! sudo -n ip link add "$host" type veth peer name "$peer" netns "$ns" 2>/dev/null; then
        NETNS_TOPOLOGY_WHY="\`ip link add $host type veth\` failed"
        return 4
    fi
    if ! sudo -n ip addr add "$host_cidr" dev "$host" 2>/dev/null \
        || ! sudo -n ip link set "$host" up 2>/dev/null \
        || ! sudo -n ip netns exec "$ns" ip addr add "$peer_cidr" dev "$peer" 2>/dev/null \
        || ! sudo -n ip netns exec "$ns" ip link set "$peer" up 2>/dev/null \
        || ! sudo -n ip netns exec "$ns" ip link set lo up 2>/dev/null; then
        NETNS_TOPOLOGY_WHY="addressing $host/$peer failed after both links existed"
        return 4
    fi
    NETNS_TOPOLOGY_WHY=""
    return 0
}

# Can this host build one at all? Builds a throwaway and deletes it, so the
# answer is a measurement rather than a reading of a knob.
netns_topology_probe() {
    local rc
    netns_topology_up probe 10.253.0.1/30 10.253.0.2/30
    rc=$?
    netns_topology_down probe
    return $rc
}

# `bash netns-topology.sh --selftest` — the real construction, plus the
# REACHABILITY that makes it a topology rather than two unrelated interfaces,
# plus the teardown leaving nothing behind.
if [[ "${BASH_SOURCE[0]}" == "${0}" && "${1:-}" == "--selftest" ]]; then
    trap 'netns_topology_down st' EXIT
    if netns_topology_up st 10.252.0.1/30 10.252.0.2/30; then
        if sudo -n ip netns exec wznsst ping -c1 -W2 10.252.0.1 >/dev/null 2>&1; then
            echo "  netns-topology selftest: built wznsst, peer reaches the host end"
        else
            echo "  netns-topology selftest FAIL: built, but the peer cannot reach 10.252.0.1" >&2
            exit 1
        fi
        netns_topology_down st
        if ip netns list 2>/dev/null | grep -q '^wznsst'; then
            echo "  netns-topology selftest FAIL: teardown left wznsst behind" >&2
            exit 1
        fi
        echo "  netns-topology selftest: teardown left nothing behind"
        exit 0
    fi
    rc=$?
    if (( rc == 4 )); then
        echo "  netns-topology selftest FAIL: $NETNS_TOPOLOGY_WHY" >&2
        exit 1
    fi
    echo "  netns-topology selftest SKIP: $NETNS_TOPOLOGY_WHY"
    exit 0
fi
