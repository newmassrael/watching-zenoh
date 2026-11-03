#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# One null protocol of the validation corpus (docs/flow-zenoh-verdict.md
# §6.12), run by scripts/capture-validation.sh: the protocol's real server in a
# container on a docker network of its own, tcpdump in the server's network
# namespace from when the server is up, and the protocol's real client
# talking to it, into $RAW/null-<protocol>.pcap and its log beside it.
# Every protocol here is one the development corpus (captures/corpus/) does not
# hold, and each is a group of its own (section 6.3).
#
#     IMAGE=<capture image> RAW=<dir> null-workload.sh <protocol>
set -uo pipefail

P="$1"
NET="wzval-$P"
SRV="wzval-$P-srv"
CAP="wzval-$P-cap"
LOG="$RAW/null-$P.log"
: > "$LOG"

cleanup() {
    docker rm -f "$CAP" "$SRV" > /dev/null 2>&1
    docker network rm "$NET" > /dev/null 2>&1
}
trap cleanup EXIT
cleanup
docker network create "$NET" > /dev/null || exit 2

server() {
    docker run -d --name "$SRV" --network "$NET" --network-alias srv "$@" >> "$LOG" 2>&1
}

# The server's TCP port answers, within a minute.
ready() {
    local port="$1" extra="${2:-0}"
    for _ in $(seq 1 60); do
        if docker run --rm --network "$NET" "$IMAGE" \
            bash -c "exec 3<>/dev/tcp/srv/$port" > /dev/null 2>&1; then
            sleep "$extra"
            return 0
        fi
        sleep 1
    done
    echo "null-workload: $P: port $port never answered" >> "$LOG"
    docker logs "$SRV" >> "$LOG" 2>&1
    return 1
}

# The server's IPv4 traffic with the containers of its network. The network's
# gateway is this host, whose own announcements (mDNS with its name, router
# solicitations) reach the bridge too and are not the protocol's.
capture() {
    local gw
    gw="$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "$NET")"
    docker run -d --name "$CAP" --network "container:$SRV" \
        --cap-add NET_RAW --cap-add NET_ADMIN -v "$RAW:/out" "$IMAGE" \
        tcpdump -i eth0 -U -s 0 -w "/out/null-$P.pcap" "ip and not host $gw" >> "$LOG" 2>&1
    sleep 2
}

client() {
    echo "client: $*" >> "$LOG"
    timeout 180 docker run --rm --network "$NET" "$@" >> "$LOG" 2>&1
    echo "client exit $?" >> "$LOG"
}

finish() {
    sleep 2
    docker stop -t 3 "$CAP" > /dev/null 2>&1
}

PY=python:3.12-slim
pyclient() { client -e PIP_ROOT_USER_ACTION=ignore "$PY" sh -c "pip install -q $1 && python -c '$2'"; }

case "$P" in
mariadb)
    server -e MARIADB_ROOT_PASSWORD=pw mariadb:11
    ready 3306 15 || exit 1
    capture
    client mariadb:11 mariadb -h srv -uroot -ppw -e \
        "create database t; use t; create table x (a int, b text); insert into x values (1,'one'),(2,'two'); select * from x; drop database t;" ;;
mongo)
    server mongo:7
    ready 27017 3 || exit 1
    capture
    client mongo:7 mongosh --quiet mongodb://srv/t --eval \
        'db.x.insertMany([{a:1},{a:2}]); printjson(db.x.find().toArray()); db.dropDatabase()' ;;
memcached)
    server memcached:1.6-alpine
    ready 11211 || exit 1
    capture
    client memcached:1.6-alpine sh -c \
        'printf "set k 0 0 5\r\nhello\r\nget k\r\nincr n 1\r\nset n 0 0 1\r\n7\r\nincr n 5\r\nstats\r\nquit\r\n" | nc srv 11211' ;;
nats)
    server nats:2-alpine
    ready 4222 || exit 1
    capture
    client natsio/nats-box:latest sh -c \
        'nats -s nats://srv:4222 sub "demo.>" --count 5 & sleep 2; for i in 1 2 3 4 5; do nats -s nats://srv:4222 pub demo.a "hello $i"; done; wait' ;;
rabbitmq)
    server rabbitmq:3-alpine
    ready 5672 10 || exit 1
    capture
    pyclient pika 'import pika
c = pika.BlockingConnection(pika.ConnectionParameters("srv"))
ch = c.channel()
ch.queue_declare(queue="q")
for i in range(5):
    ch.basic_publish(exchange="", routing_key="q", body=b"hello %d" % i)
for m in ch.consume("q", inactivity_timeout=2):
    if m[0] is None:
        break
    ch.basic_ack(m[0].delivery_tag)
c.close()' ;;
ldap)
    server osixia/openldap:1.5.0
    ready 389 5 || exit 1
    capture
    client --entrypoint ldapsearch osixia/openldap:1.5.0 -x -H ldap://srv \
        -b dc=example,dc=org -D cn=admin,dc=example,dc=org -w admin ;;
git)
    server alpine:3.20 sh -c \
        'apk add -q git git-daemon && mkdir -p /r/x && cd /r/x && git init -q && head -c 50000 /dev/urandom > f && git add f && git -c user.email=a@b -c user.name=a commit -q -m one && exec git daemon --reuseaddr --export-all --base-path=/r /r'
    ready 9418 || exit 1
    capture
    client alpine:3.20 sh -c 'apk add -q git && git clone -q git://srv/x /tmp/x && ls -la /tmp/x' ;;
rsync)
    server alpine:3.20 sh -c \
        'apk add -q rsync && mkdir /d && head -c 200000 /dev/urandom > /d/f && printf "[d]\npath = /d\nuse chroot = no\nread only = yes\n" > /etc/rsyncd.conf && exec rsync --daemon --no-detach'
    ready 873 || exit 1
    capture
    client alpine:3.20 sh -c 'apk add -q rsync && rsync -av rsync://srv/d/ /tmp/d/' ;;
iperf3-tcp|iperf3-udp)
    server networkstatic/iperf3 -s
    ready 5201 || exit 1
    capture
    # A megabyte each: the protocol is its control channel and the shape of
    # its test stream, which a megabyte shows as well as a line rate does.
    if [[ $P == iperf3-udp ]]; then
        client networkstatic/iperf3 -c srv -u -b 1M -n 1M
    else
        client networkstatic/iperf3 -c srv -n 1M
    fi ;;
telnet)
    server busybox:1.36 telnetd -F -l /bin/sh
    ready 23 || exit 1
    capture
    client busybox:1.36 sh -c '(sleep 1; echo "ls /"; sleep 1; echo "echo hello"; sleep 1; echo exit; sleep 1) | telnet srv' ;;
tftp)
    server alpine:3.20 sh -c \
        'apk add -q tftp-hpa && mkdir /t && head -c 100000 /dev/urandom > /t/f && exec in.tftpd -L -s /t'
    sleep 8
    capture
    client busybox:1.36 tftp -g -r f -l /tmp/f srv ;;
ftp)
    server -e 'USERS=u|p' delfer/alpine-ftp-server
    ready 21 || exit 1
    capture
    client busybox:1.36 sh -c 'echo hello > /tmp/up && ftpput -u u -p p srv up /tmp/up && ftpget -u u -p p srv /tmp/down up && cat /tmp/down' ;;
smb)
    server dperson/samba -s 'share;/tmp;yes;no;yes'
    ready 445 || exit 1
    capture
    client alpine:3.20 sh -c 'apk add -q samba-client && smbclient //srv/share -N -c "ls"' ;;
mail)
    server -e 'GREENMAIL_OPTS=-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.auth.disabled' \
        greenmail/standalone:2.0.1
    ready 3143 3 || exit 1
    capture
    client curlimages/curl:8.10.1 sh -c \
        'printf "Subject: hi\r\n\r\nhello\r\n" > /tmp/m; curl -s smtp://srv:3025 --mail-from a@b.org --mail-rcpt u@b.org -T /tmp/m; curl -s imap://srv:3143/INBOX -u u@b.org:u@b.org; curl -s pop3://srv:3110/ -u u@b.org:u@b.org' ;;
radius)
    server freeradius/freeradius-server:latest -X
    sleep 8
    capture
    client freeradius/freeradius-server:latest radtest bob hello srv 0 testing123 ;;
stun)
    server coturn/coturn:latest -n --log-file=stdout
    sleep 5
    capture
    client coturn/coturn:latest turnutils_stunclient srv ;;
grpc)
    server moul/grpcbin
    ready 9000 || exit 1
    capture
    client fullstorydev/grpcurl:latest -plaintext srv:9000 list
    client fullstorydev/grpcurl:latest -plaintext -d '{"greeting":"zenoh"}' srv:9000 hello.HelloService/SayHello ;;
websocket)
    server jmalloc/echo-server
    ready 8080 || exit 1
    capture
    pyclient websockets 'import asyncio, websockets
async def main():
    async with websockets.connect("ws://srv:8080/.ws") as w:
        await w.recv()
        for i in range(5):
            await w.send(bytes(range(i, i + 40)))
            await w.recv()
            await w.send("text %d" % i)
            await w.recv()
asyncio.run(main())' ;;
zeromq)
    server -e PIP_ROOT_USER_ACTION=ignore "$PY" sh -c 'pip install -q pyzmq && python -c "
import zmq
s = zmq.Context().socket(zmq.REP)
s.bind(\"tcp://*:5555\")
while True:
    s.send(b\"re:\" + s.recv())
"'
    ready 5555 || exit 1
    capture
    pyclient pyzmq 'import zmq
s = zmq.Context().socket(zmq.REQ)
s.connect("tcp://srv:5555")
for i in range(5):
    s.send(b"hello %d" % i)
    s.recv()' ;;
modbus)
    server -e PIP_ROOT_USER_ACTION=ignore "$PY" sh -c 'pip install -q pymodbus==3.7.4 && python -c "
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
b = ModbusSequentialDataBlock(0, [7] * 100)
StartTcpServer(context=ModbusServerContext(slaves=ModbusSlaveContext(hr=b, ir=b, co=b, di=b), single=True), address=(\"0.0.0.0\", 502))
"'
    ready 502 || exit 1
    capture
    pyclient pymodbus==3.7.4 'from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient("srv", port=502)
c.connect()
for i in range(5):
    c.read_holding_registers(i, count=4)
    c.write_register(i, i)
c.close()' ;;
snmp)
    server alpine:3.20 sh -c \
        'apk add -q net-snmp && printf "rocommunity public\nagentaddress udp:161\n" > /etc/snmp/snmpd.conf && exec snmpd -f -Lo -C -c /etc/snmp/snmpd.conf'
    sleep 10
    capture
    client alpine:3.20 sh -c 'apk add -q net-snmp-tools && snmpwalk -v2c -c public srv system' ;;
syslog)
    server alpine:3.20 sh -c \
        'apk add -q rsyslog && printf "module(load=\"imudp\")\ninput(type=\"imudp\" port=\"514\")\nmodule(load=\"imtcp\")\ninput(type=\"imtcp\" port=\"514\")\n*.* /tmp/all\n" > /etc/rsyslog.conf && exec rsyslogd -n'
    ready 514 || exit 1
    capture
    client alpine:3.20 sh -c \
        'apk add -q util-linux-misc && for i in 1 2 3; do logger -n srv -P 514 -d "udp $i"; logger -n srv -P 514 -T "tcp $i"; done' ;;
sip)
    server ctaloi/sipp -sn uas
    sleep 3
    capture
    client ctaloi/sipp -sn uac srv:5060 -m 5 -r 2 -timeout 20s ;;
irc)
    server inspircd/inspircd-docker
    ready 6667 3 || exit 1
    capture
    client alpine:3.20 sh -c \
        '(sleep 1; printf "NICK val\r\nUSER val 0 * :val\r\n"; sleep 3; printf "JOIN #z\r\nPRIVMSG #z :hello\r\nQUIT :bye\r\n"; sleep 2) | nc srv 6667' ;;
consul)
    server hashicorp/consul:1.19 agent -dev -client 0.0.0.0 -bind '{{ GetInterfaceIP "eth0" }}'
    ready 8301 3 || exit 1
    capture
    client hashicorp/consul:1.19 sh -c \
        'consul agent -data-dir /tmp/c -bind "{{ GetInterfaceIP \"eth0\" }}" -retry-join srv -node second & sleep 12; consul kv put -http-addr=srv:8500 z/a hello; consul members -http-addr=srv:8500; kill %1; wait' ;;
zookeeper)
    server zookeeper:3.9
    ready 2181 3 || exit 1
    capture
    client zookeeper:3.9 bin/zkCli.sh -server srv:2181 create /a hello
    client zookeeper:3.9 bin/zkCli.sh -server srv:2181 get /a ;;
beanstalkd)
    server schickling/beanstalkd
    ready 11300 || exit 1
    capture
    client alpine:3.20 sh -c \
        '(printf "put 0 0 60 5\r\nhello\r\nreserve-with-timeout 1\r\nstats\r\nquit\r\n"; sleep 2) | nc srv 11300' ;;
nsq)
    server nsqio/nsq /nsqd
    ready 4150 || exit 1
    capture
    client nsqio/nsq sh -c \
        '/nsq_tail -nsqd-tcp-address srv:4150 -topic t -n 3 & sleep 2; printf "a\nb\nc\n" | /to_nsq -nsqd-tcp-address srv:4150 -topic t; wait' ;;
*)
    echo "null-workload: no such protocol: $P" >> "$LOG"
    exit 2 ;;
esac
finish
[[ -s "$RAW/null-$P.pcap" ]]
