# Captures of upstream software

Real captures of upstream zenoh, each taken to hold one behaviour of this
workspace's reader to the bytes upstream writes, and read by
`crates/wz-capture/src/upstream_capture_tests.rs`.

They are real captures, as the files of `../corpus/` are, and are anonymised
the same way (`scripts/lib/capture_anonymise.py`, scope `own`: the capturer
started every container on a network of its own), with `corpus.json5` here
saying what each one is. They are NOT in the calibration corpus, and that is
the reason this directory exists: every zenoh file of `../corpus/` feeds the
counts model 2 of the zenoh verdict is computed from
(`crates/wz-capture/src/zenoh_corpus_tests.rs`,
`the_corpus_measures_the_counts_model_two_is_computed_from`), so a capture added
there to hold a behaviour would move the verdict's weights as a side effect.
A file here can join the corpus when the verdict's owner decides to measure
it.

`.githooks/pre-push` holds every file here to being a fixed point of the
anonymiser (`capture_anonymise.py --verify-corpus captures/upstream`), as it
does the corpus.

## `zenoh-1-10-0-udp-multicast.pcap`

Two stock `eclipse/zenoh:1.10.0` peers on one UDP multicast group, and 30 PUTs.

| | |
|---|---|
| link type | 1 (`LINKTYPE_ETHERNET`), the bridge of a docker network of its own |
| packets | 42: each peer's JOIN every 2.5 s (6 each), and the 30 PUTs, one FRAME a datagram |
| flows | 2, one per peer's sending socket, toward `224.0.0.224:7447` |
| JOINs | header `0xa7` (Z and T set, S clear), version 9: the default ring, stated |
| taken | 2026-11-02 |

Both peers ran `mode: "peer"`, listened on `udp/224.0.0.224:7447`, and had
multicast scouting and gossip off. One ran the REST plugin on port 8000 and was
sent `PUT /demo/sample` 30 times, 100 ms apart, with the bodies `value 1` to
`value 30`; the other ran the storage manager with a memory storage on
`demo/**` and timestamping on, which the storage manager requires. `tcpdump -i
<bridge> 'udp port 7447'` ran from before either peer started, so each flow's
first message is its sender's first JOIN.

### What it holds

A sender's FRAME SNs on a multicast group are judged on the ring its JOIN
states and from the `next_sn` it states. As captured, every one of the 30 frames
after the JOINs is judged and none is missing; with one frame taken out, one SN
is missing, whichever frame it is, except the last, which no later frame
reveals. The JOINs state the default ring because stock zenohd writes no other
(`io/zenoh-transport/src/multicast/link.rs` @ `resolution: Resolution::default(),`),
whatever `transport.link.tx.sequence_number_resolution` says; a JOIN that states
another ring is held in `wz-session-core` (`passive::join_ring_tests`).

### Taking it again

Run two such peers on a docker bridge network, capture the bridge, PUT through
the REST peer, then:

```sh
python3 scripts/lib/capture_anonymise.py --in raw.pcap \
    --out captures/upstream/zenoh-1-10-0-udp-multicast.pcap --scope own
```

The SNs start at a random value and the zids are new on every run, so a new
capture is a new file: the tests read the counts above, not its bytes.
