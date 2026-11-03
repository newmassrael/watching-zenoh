#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# One zenoh workload of the validation corpus (docs/flow-zenoh-verdict.md
# §6.12), run inside the capture container by scripts/capture-validation.sh:
#
#     zenoh-workload.sh <workload> <out-dir>
#
# The programs are in /z (the pinned release's zenohd and examples, see
# build-bins.sh), the zenoh-c and zenoh-pico examples in /zc and /zp when the
# workload uses them. Everything runs on the container's loopback, which
# tcpdump captures from before the first process starts to after the last one
# ends, into <out-dir>/<workload>.pcap; each program's output goes to
# <out-dir>/<workload>.log. Every workload is one group of section 6.3 (a
# workload, a link, an implementation), and lasts about twenty seconds.
set -uo pipefail

W="$1"
OUT="$2"
Z=/z
LOG="$OUT/$W.log"
: > "$LOG"
PIDS=()

say() { printf '[%s] %s\n' "$W" "$*" >> "$LOG"; }

# A program in the background, its output into the log.
bg() {
    say "start: $*"
    "$@" >> "$LOG" 2>&1 &
    PIDS+=("$!")
}

# A program in the foreground, bounded: interrupted after FG_LIMIT seconds,
# then killed. The first word may be `client`, which a subshell runs and the
# program replaces, so the pid waited on is the program's.
fg() {
    say "run: $*"
    ("$@") >> "$LOG" 2>&1 &
    local p=$!
    (sleep "${FG_LIMIT:-15}"; kill -INT "$p" 2>/dev/null; sleep 2; kill -KILL "$p" 2>/dev/null) &
    local w=$!
    wait "$p"
    local rc=$?
    kill "$w" 2>/dev/null
    wait "$w" 2>/dev/null
    say "exit $rc"
}

# Every program the workload started is one of the mounted ones, and the
# container is the workload's own: they end by name, the clients first.
stop_all() {
    pkill -INT -f '^/z[cp]?/z_' 2>/dev/null
    sleep 2
    pkill -INT -f '^/z/zenohd' 2>/dev/null
    sleep 2
    pkill -KILL -f '^/z[cp]?/' 2>/dev/null
    wait "${PIDS[@]}" 2>/dev/null
}

ip link set lo up
ip link set lo multicast on
ip route add 224.0.0.0/4 dev lo 2>/dev/null
tcpdump -i lo -U -s 0 -w "$OUT/$W.pcap" >> "$LOG" 2>&1 &
CAP=$!
sleep 1

T=tcp/127.0.0.1:7447
U=udp/127.0.0.1:7447
NOSCOUT=--no-multicast-scouting
big() { head -c "$1" /dev/zero | tr '\0' 'z'; }
router() { bg "$Z/zenohd" "$NOSCOUT" "$@"; sleep 2; }
# A client of the router at <endpoint>: always run in a subshell (by bg or fg),
# which the program replaces.
client() { local e="$1"; shift; exec "$@" -m client -e "$e" "$NOSCOUT"; }

# A subscriber and a publisher. The publisher's payload is PAYLOAD when set: a
# program argument is at most 128 KiB, so a payload is at most 100 000 bytes.
pubsub() {
    local e="$1"; shift
    local pay=()
    [[ -n ${PAYLOAD:-} ]] && pay=(-p "$PAYLOAD")
    bg client "$e" "$Z/z_sub" -k 'demo/**' "$@"
    sleep 1
    bg client "$e" "$Z/z_pub" -k demo/a "${pay[@]}" "$@"
    sleep 12
}

query() {
    local e="$1"; shift
    bg client "$e" "$Z/z_queryable" -k demo/q "$@"
    sleep 1
    for _ in 1 2 3 4 5 6; do
        fg client "$e" "$Z/z_get" -s 'demo/**' -o 2000 "$@"
    done
}

liveliness() {
    local e="$1"; shift
    bg client "$e" "$Z/z_sub_liveliness" -k 'group1/**' "$@"
    sleep 1
    bg client "$e" "$Z/z_liveliness" -k group1/a "$@"
    sleep 2
    for _ in 1 2 3; do
        fg client "$e" "$Z/z_get_liveliness" -k 'group1/**' "$@"
    done
    sleep 3
}

# A CA of the workload's own and a server certificate it signed: rustls does not
# take a self-signed end-entity certificate as its own root.
certs() {
    {
        openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=wz-validation-ca \
            -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
            -keyout /tmp/ca-key.pem -out /tmp/ca.pem
        openssl req -newkey rsa:2048 -nodes -subj /CN=localhost \
            -keyout /tmp/key.pem -out /tmp/server.csr
        printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n' > /tmp/ext.cnf
        openssl x509 -req -in /tmp/server.csr -CA /tmp/ca.pem -CAkey /tmp/ca-key.pem \
            -CAcreateserial -days 2 -extfile /tmp/ext.cnf -out /tmp/cert.pem
    } >> "$LOG" 2>&1
}

case "$W" in
query-tcp) router -l "$T"; query "$T" ;;
query-udp) router -l "$U"; query "$U" ;;
liveliness-tcp) router -l "$T"; liveliness "$T" ;;
liveliness-udp) router -l "$U"; liveliness "$U" ;;
fragments-tcp)
    router -l "$T"
    PAYLOAD="$(big 100000)" pubsub "$T" ;;
fragments-udp)
    router -l "$U"
    PAYLOAD="$(big 30000)" pubsub "$U" ;;
priority-tcp)
    router -l "$T"
    # Two publishers the publication QoS puts at two priorities, one express.
    bg client "$T" "$Z/z_sub" -k 'demo/**'
    sleep 1
    bg client "$T" "$Z/z_pub" -k demo/hi --cfg \
        'qos/publication:[{key_exprs:["demo/hi"],config:{priority:"real_time",express:true}}]'
    bg client "$T" "$Z/z_pub" -k demo/lo --cfg \
        'qos/publication:[{key_exprs:["demo/lo"],config:{priority:"background"}}]'
    sleep 12 ;;
auth-tcp)
    printf 'alice:secret\n' > /tmp/users.txt
    router -l "$T" --cfg 'transport/auth/usrpwd/dictionary_file:"/tmp/users.txt"'
    cred=(--cfg 'transport/auth/usrpwd/user:"alice"' --cfg 'transport/auth/usrpwd/password:"secret"')
    pubsub "$T" "${cred[@]}"
    query "$T" "${cred[@]}" ;;
multicast-peers)
    M='udp/224.0.0.225:7447#iface=lo'
    bg "$Z/z_sub" -k 'demo/**' -m peer -l "$M" "$NOSCOUT"
    sleep 1
    bg "$Z/z_pub" -k demo/m -m peer -l "$M" "$NOSCOUT"
    sleep 14 ;;
lowlatency-tcp|lowlatency-udp)
    e=$T; [[ $W == lowlatency-udp ]] && e=$U
    ll=(--cfg 'transport/unicast/lowlatency:true' --cfg 'transport/unicast/qos/enabled:false')
    router -l "$e" "${ll[@]}"
    pubsub "$e" "${ll[@]}"
    query "$e" "${ll[@]}" ;;
ws)
    router -l ws/127.0.0.1:8000
    pubsub ws/127.0.0.1:8000
    query ws/127.0.0.1:8000 ;;
peer-tcp)
    bg "$Z/z_sub" -k 'demo/**' -m peer -l tcp/127.0.0.1:7448 "$NOSCOUT"
    sleep 1
    bg "$Z/z_pub" -k demo/p -m peer -e tcp/127.0.0.1:7448 "$NOSCOUT"
    sleep 12 ;;
routers-tcp)
    router -l "$T"
    router -l tcp/127.0.0.1:7449 -e "$T"
    bg client tcp/127.0.0.1:7449 "$Z/z_sub" -k 'demo/**'
    sleep 1
    bg client "$T" "$Z/z_pub" -k demo/r
    sleep 12 ;;
ipv6-tcp)
    router -l 'tcp/[::1]:7447'
    pubsub 'tcp/[::1]:7447'
    query 'tcp/[::1]:7447' ;;
lz4-tcp)
    lz=(--cfg 'transport/unicast/compression/enabled:true')
    router -l "$T" "${lz[@]}"
    PAYLOAD="$(big 4000)" pubsub "$T" "${lz[@]}"
    query "$T" "${lz[@]}" ;;
advanced-tcp)
    router -l "$T"
    bg client "$T" "$Z/z_advanced_pub" -k demo/adv --history 10
    sleep 3
    bg client "$T" "$Z/z_advanced_sub" -k 'demo/**'
    sleep 12 ;;
churn-tcp)
    router -l "$T"
    bg client "$T" "$Z/z_sub" -k 'demo/**'
    sleep 1
    for i in $(seq 1 30); do
        FG_LIMIT=5 fg client "$T" "$Z/z_put" -k "demo/c$i" -p "put $i"
    done ;;
ping-tcp)
    router -l "$T"
    bg client "$T" "$Z/z_pong"
    sleep 1
    FG_LIMIT=12 fg client "$T" "$Z/z_ping" -w 0 -n 200 64 ;;
scouting)
    bg "$Z/zenohd" -l "$T"
    sleep 2
    FG_LIMIT=5 fg "$Z/z_scout"
    bg "$Z/z_sub" -k 'demo/**' -m peer
    sleep 1
    bg "$Z/z_pub" -k demo/s -m peer
    sleep 10 ;;
tls-tcp|quic)
    certs
    proto=tls; [[ $W == quic ]] && proto=quic
    e="$proto/localhost:7447"
    lc=(--cfg 'transport/link/tls/listen_private_key:"/tmp/key.pem"'
        --cfg 'transport/link/tls/listen_certificate:"/tmp/cert.pem"')
    cc=(--cfg 'transport/link/tls/root_ca_certificate:"/tmp/ca.pem"')
    router -l "$e" "${lc[@]}"
    pubsub "$e" "${cc[@]}"
    query "$e" "${cc[@]}" ;;
admin-query)
    router -l "$T"
    bg client "$T" "$Z/z_sub" -k 'demo/**'
    sleep 1
    for _ in 1 2 3 4; do fg client "$T" "$Z/z_get" -s '@/**' -o 2000; done ;;
querier-tcp)
    router -l "$T"
    bg client "$T" "$Z/z_queryable" -k demo/q
    sleep 1
    FG_LIMIT=12 fg client "$T" "$Z/z_querier" -s 'demo/**' ;;
zenoh-c-pubsub|zenoh-c-query|pico-pubsub-tcp|pico-pubsub-udp|pico-query-tcp)
    X=/zc; [[ $W == pico-* ]] && X=/zp
    e=$T; [[ $W == pico-pubsub-udp ]] && e=$U
    router -l "$e"
    case "$W" in
    *pubsub*)
        bg "$X/z_sub" -e "$e"
        sleep 1
        bg "$X/z_pub" -e "$e"
        sleep 12 ;;
    *query*)
        bg "$X/z_queryable" -e "$e"
        sleep 1
        for _ in 1 2 3 4 5; do fg "$X/z_get" -e "$e"; done ;;
    esac ;;
*)
    say "no such workload"
    kill "$CAP"
    exit 2 ;;
esac

stop_all
sleep 1
kill -INT "$CAP"
wait "$CAP" 2>/dev/null
say "done"
