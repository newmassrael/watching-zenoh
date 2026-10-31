# Whether a flow is zenoh: a sequential test over state invariants

Status: design note. It states what is built, what is decided and what is
still open. It is not a specification and the atomic store does not parse it.
It answers a consumer claim filed on 2026-10-26: move the per-flow zenoh
verdict from a fixed rule to a sequential probability ratio test whose
thresholds wz owns, so that a consumer draws the verdict and its basis
instead of holding thresholds of its own.

## 1. The question

A passive reader is handed a flow and must say whether its bytes are zenoh.
Until this note the answer was a rule (field document revision 41 to 42,
session table revision 3 to 4): `proven` when at least one Init, Join, Scout or
Hello of version 0x09 decoded from a framing unit read whole, and no message of
another version did. Two defects follow from that rule, both measured:

- **One header is a verdict.** A DNS id of `0x6109` or `0x4709` writes a Scout
  or a Join header followed by the version byte, and the flow is `proven`
  (`a_dns_datagram_whose_id_reads_as_a_join_header_is_proven`, 2 in 4200
  generated DNS flows).
- **Everything else is `unproven`.** A zenoh session the capture joined after
  its handshake carries no Init, so it gets the word arbitrary bytes get, and
  the consumer was left to separate the two with its own thresholds on
  `unit_readings` (ten units, a share of 0.75). Generated structured protocols
  reach a share of 0.6 at ten units
  (`structured_datagrams_of_other_protocols_read_by_their_first_byte`).

## 2. The test

Two hypotheses about one flow. H1: the bytes are zenoh transport as this
reader reads it (protocol version 0x09). H0: they are not. A zenoh flow of
another version is a separate question, answered by its own cell (section 4).

Each observation `o` adds `log2(P(o | H1, past) / P(o | H0, past))` to the
flow's log likelihood ratio `L`. The verdict is read off `L` against two
thresholds fixed by the error rates:

| verdict | condition |
|---|---|
| `yes` | `L >= log2(1/alpha)` |
| `no` | `L <= log2(beta)` |
| `undecided` | otherwise |

`alpha = beta = 2^-20`, so the thresholds are +20 and -20 bits.

**The verdict is reported at every moment, not frozen at the first
crossing.** That is sound because, when every increment is a true conditional
likelihood ratio, `2^L` is a nonnegative martingale under H0, and Ville's
inequality bounds the chance that it EVER reaches `1/alpha` by `alpha`
(and symmetrically for H1 and `beta`). The bound covers a live tap that reads
the verdict after every packet. Wald's `(1 - beta) / alpha` is not used: it
assumes one decision at a stopping time.

**Several null protocols, two statistics (model 2).** H0 is a family (DNS,
mDNS, SSDP, RTPS, ...). For an outcome whose H0 probability differs across the
family, the `yes` statistic uses the LARGEST probability any member shows. It
is then at most the true ratio against every member, so the false `yes` is
bounded against each member of the corpus at once. Those largest
probabilities sum to more than one over an observation's outcomes, so the
same statistic read for `no` bounds nothing: under H1, `2^-L` is a martingale
only when the denominator is a proper distribution. The `no` statistic uses
one, the average of the members' (any proper distribution bounds the false
`no`). Each observation therefore weighs twice, `yes` is read on the first sum
and `no` on the second, and a flow whose two sums both cross is `undecided`.
Model 1 kept one sum and claimed both bounds; only the false `yes` held. An
observation must also be weighed on every outcome it can have: one weighed
only when it confirms (model 1's `version_header`) raises the `yes`
statistic's expectation under H0. Neither bound holds against a protocol the
corpus does not contain; that is the limit the claim states and the reason
for section 6.

**The port is not evidence.** The thresholds are a statement about the bytes
under H0, and a prior odds from the port would move that statement by an
amount nobody has measured. A posterior beside the verdict needs base rates
per port, which only a corpus of real captures gives (section 6).

## 3. The observations (model 1)

This section is model 1, kept as it was written; model 2 (section 6.2)
measures the unit weights, adds `stream_framing`, weighs another version
against the flow and keeps two sums.

Each check has a strength, a probability under H0 (`q`, the chance a
non-zenoh flow satisfies it) and a probability under H1 (`eps`, the chance a
zenoh flow fails it: loss, reordering, a capture that began mid-session).
Each side of each check names its basis: `derived` from field widths,
`generated` from the generated corpus in
`crates/wz-capture/src/session_table_tests.rs`, or `assumed` and waiting for a
measurement. Weights are written in millibits.

| check | strength | observed when | confirm | violate | q basis | eps basis |
|---|---|---|---|---|---|---|
| `cookie_echo` | `handshake` | an OpenSyn follows an InitAck of the other direction, both read whole | `8000 * min(len, 8) - 1` | `-10000` | derived: `2^-(8 len)`, capped at the 64-bit hash | assumed: `2^-10` |
| `init_roles` | `handshake` | both directions sent an Init read whole | `999` | `-9000` | derived: `1/2`, two Inits of opposite kind by chance | assumed: `2^-10` |
| `sn_follows` | `state` | a Frame or Fragment after an earlier one on its conduit | `7907` | `-3994` | derived: a varint equals a given value with chance at most `2^-8` | assumed: `2^-4` |
| `version_header` | `header` | an admissible Init, Join, Scout or Hello of version 0x09 read whole | `8000` | none | derived: the version byte, `2^-8` | none: another version is the version cell's question |
| `unit_reading` | `unit` | every framing unit | `2603` (explained) | `-6745` (residual), `-7000` (undecoded) | generated: the largest share over the corpus (mDNS 0.162 explained, mDNS 0.838 residual, SSDP 1.0 undecoded) | assumed: `2^-7` each for residual and undecoded |

Notes on the table:

- `sn_follows` is judged WITHOUT the ring when no InitAck or Join gave one: the
  step "the next integer" needs no mask, which is the rule the reassembly
  dispatcher already applies to a chain it follows without a ring. This is
  what lets a session the capture joined after its handshake reach `yes`.
- `q` for `sn_follows` is exact only against bytes that do not count. A
  protocol with a counter where a zenoh SN would sit (a CoAP message id, an
  RTPS sequence number) can beat it. That is a measurement for section 6, not
  a bound this note can claim.
- The kind of a unit's front message is assumed to carry no evidence beyond
  the checks above. It is neither a conservative nor an anti-conservative
  assumption, and the corpus replaces it.
- Each of the eight model constants is written as a literal and recomputed
  from its stated probabilities by a test, so a literal cannot drift from its
  derivation.

What this gives, worked out from the table:

- The DNS datagram whose id reads as a Join: `2603 + 8000` = 10.6 bits,
  `undecided`. A DNS flow of ten datagrams: about eight undecoded units, `no`
  after three.
- A zenoh session joined mid-stream: each Frame unit adds `2603 + 7907` once
  its conduit has a baseline, `yes` after two or three units.
- A full handshake: the cookie alone is 64 bits, `yes` on the OpenSyn.

## 4. The documents

The `zenoh` key keeps its name and takes the words `yes`, `no`, `undecided`.
Two keys arrive beside it on every flow object of the field document and on
every row and flow of the session table:

- `announced_version`: `none`, `own`, `foreign`, `mixed`. What the
  version-bearing messages said, the old rule's evidence kept as a separate
  answer.
- `zenoh_evidence`: `{"log2_lr_millibits": L, "yes_at_millibits": 20000,
  "no_at_millibits": -20000, "model": 1, "checks": [...]}`, one entry per check
  that observed anything: `check`, `strength`, `confirmed`, `violated`,
  `millibits`, `q_basis`, `eps_basis`.

The field document moves to revision 43 and the session table to revision 5.
The value change is the notice a revision row carries
(`crates/wz-capture/src/doc_revision.rs` @ `R2175 (open-debt item 552) — THE VALUE FAMILIES`).
The selector's `zenoh` term takes the new words.

## 5. Not in model 1, and why

- **A declared id referenced later, a request answered, a KeepAlive inside the
  lease.** The reader decides the first two only from held messages
  (`crates/wz-capture/src/interest.rs`, `crates/wz-capture/src/exchange.rs`),
  so they do not survive a retention ceiling, and nothing compares KeepAlive
  spacing with the lease. Each needs an ingest-time tally first. Their `eps`
  also depends on where the capture began (a declaration made before the
  capture reads as unresolved), which needs real H1 captures to price.
- **Fragment reassembly** beyond the SN steps already counted: its independent
  part is whether the joined batch parses, whose `q` needs a corpus.

## 6. Steps after model 1

1. **Corpus.** H1: real zenoh captures, mid-session, lz4, several versions. H0
   from real devices: mDNS, DNS, SSDP, RTPS, SOME/IP first, then LLMNR,
   WS-Discovery, NTP, DHCP, CoAP, MQTT, QUIC, and structured TCP (HTTP, MQTT,
   TLS). Real captures are committed under `captures/` after anonymisation
   (addresses, MACs, host and service names replaced, payload layout kept;
   owner decision 2026-10-26).
2. **ROC gate.** The false `yes` rate over H0 and the false `no` rate over H1,
   measured per protocol, held by a test as a regression.
3. **Measured weights.** The `generated` and `assumed` sides are replaced by
   measured ones and the model number moves.

### 6.1 Where steps 1 and 2 stand (2026-10-26)

The corpus is `captures/corpus/`, described file by file in its
`corpus.json5`, and the ROC test is `crates/wz-capture/src/zenoh_corpus_tests.rs`:
no flow of an `other` file may read `yes`, no flow of a `zenoh` file may read
`no`, and every file's tally of the three words is pinned for both builds (with
and without lz4). The anonymiser is `scripts/lib/capture_anonymise.py`; its
selftest and `--verify-corpus` run in the pre-push static gate array.

It holds six zenoh 1.10.1 captures (TCP and UDP, from before the handshake and
joined mid-session, with and without lz4), three of an office Wi-Fi (DNS,
mDNS, SSDP), and the real implementations of MQTT (mosquitto), RTPS (ROS 2
Jazzy), CoAP (libcoap), SOME/IP (vsomeip) and HTTP/3 over QUIC versions 1 and
2 (aioquic) run in containers. Every zenoh flow reads `yes`; no flow of the
others reads `yes`. Every QUIC connection reads `undecided`, which is the
honest word: zenoh runs over QUIC as well, and a protected flow shows nothing
that tells the two apart.

A TCP flow of another protocol whose bytes never frame a unit carries nothing
model 1 weighs, and reads `undecided`: forty short MQTT connections do. A
framing that never takes, measured as the stream's desynchronisations without a
recovery, is evidence model 1 does not count yet; it is a check for step 3,
with its weights from this corpus.

**The corpus's first finding** was a false `no`: both flows of a compressed UDP
session joined mid-session read `no`. With no Init in the capture nothing told
the reader that every batch opens with a header byte, so it read that byte as a
message and every unit as undecodable. The reader now infers the header from
the bytes where no Init was seen (`FlowContext::batch_header`, the halves'
`batch_header` from field document revision 44): a unit that reads whole only
behind a header byte makes a datagram direction headed, a unit that reads whole
only as it stands makes it plain again, and a stream finds its framing again on
a chain of boundaries all in one of the two readings. The model did not move;
the evidence was misread.

What the header showed is also a negotiated value the handshake would have
stated: a batch header means the session negotiated compression, and a batch
that reads whole without one means it did not. From field document revision 45
each flow's `context.parameters` carries every negotiated value beside its
basis (`stated`, `inferred`, `conflicting`, `absent`), and `compression` is the
one the bytes can infer, with the counts it rests on per direction
(`PassiveSession::compression_reading`). On the corpus every capture that
holds the handshake states its compression and every one joined mid-session
infers the same value.

A busier network's own protocols are in the corpus too, from real
implementations in containers: DHCP between twelve clients and a server, NTP
between six clients and a server, LLMNR and WS-Discovery between a file server
and four askers. No flow of them reads `yes`. HTTP/1.1 and TLS 1.2 and 1.3
(34 connections each, python's server and OpenSSL 3) are in too, and the
reader frames no unit of them and loses no framing: the stream reader never
sees them. A flow whose first bytes are `GET ` or `HTTP` is read as a
WebSocket carrier (`ws::http_upgrade_verdict`) and one that opens with a TLS
ClientHello as an encrypted one, whatever the size of what follows (bodies of
25000 and 70000 bytes measured the same), so all 68 flows stay `undecided`
with nothing weighed. A connection that opens with another method does reach
the stream reader, which takes `PO`, `PU` or `HE` for a length prefix: 28
such connections (POST, PUT and HEAD, bodies up to 30000 bytes) stay
`undecided`, and each of the 50 directions captured from its start loses its
framing before it frames a unit. That is the first framing the null side
observed beside MQTT's, and it moves the weights of a held framing.

Two database protocols reach the stream reader too, since neither opens with
`GET `, `HTTP` or a ClientHello: Redis (RESP; 60 connections, a one-shot
client, a pipelining one and a small benchmark) and PostgreSQL (24
connections). Neither flow reads `yes`. Redis frames no
unit and loses the framing of all 120 directions. PostgreSQL frames 531 units
and every one of them has bytes left over (a residual unit), loses 48
directions, and three of its connections carry enough of them to read `no`.
The 531 residual units put the null side's unit share of a unit read whole
lower, which raised that unit's `no` weight to within a few millibits of a
broken SN step's -3994: a flow of units that read whole and repeat an SN
weighs little either way, and the ordered-fold test that builds such a flow
takes its length from the two weights and fails with a sentence when the
margin turns positive.

Two more protocols reach it: SSH (OpenSSH; 17 sessions under three ciphers, a
pty and 2 MB each way; 1225 packets) and SMTP (aiosmtpd and smtplib; 10
sessions, three of them upgraded with STARTTLS; 413 packets). Neither reads
`yes`. SSH reads 2 `no` and 15 `undecided`: of its 93 units 33 read whole, 20
leave bytes over and 40 do not decode, it loses the framing in all 34
directions, and 29 of its SN steps break and none follow. SMTP frames no unit,
loses the framing in all 20 directions and reads 10 `undecided`. SSH's whole
units raise the null side's share of a unit read whole, so that unit's `no`
weight fell from +3983 to +3546, and a unit read whole on a broken step now
sums to -448 on the `no` sum (it was -11): a flow of such frames leans toward
`no` a little instead of staying level. The `yes` weight of a unit read whole
is still mDNS's bound. The held framing's `yes` weight fell from +4032 to
+2835, since SSH's 0 held in 34 directions is a looser bound than
PostgreSQL's 0 in 48. No other capture changed word.

Still to come for step 2: further zenoh versions and links on the zenoh side.

### 6.2 Model 2: measured weights, two sums (step 3, 2026-10-26)

The field document's revision 46 and the session table's revision 6 carry
model 2 (`crates/wz-capture/src/zenoh_evidence.rs`). Three things move.

**Two sums** (section 2): `log2_lr_millibits` is read for `yes`,
`log2_lr_no_millibits` for `no`, and each check carries `millibits` and
`no_millibits`. A check whose null chance is derived from field widths weighs
the same in both.

**Measured weights.** Every check's zenoh side but the SN steps', and the
null side of `unit_reading` and the new `stream_framing`, take their
probabilities from the counts of `captures/corpus/` (written out in
`model::measured`, re-measured by
`the_corpus_measures_the_counts_model_two_is_computed_from`, and turned into
the weights by `model_weights_are_their_stated_probabilities`):

- zenoh's chance of each failure is the one-sided 95% Clopper-Pearson upper
  bound on its count, and the confirming outcome takes the rest: 0 residual
  and 0 undecoded in 33466 units; 0 framings lost in 456 directions held from
  their start; 0 differing cookies in 460 echoes; 0 Init pairs of one kind in
  462; 0 other versions in 924 version headers. The zenoh files are 1.10.1
  routers and clients, upstream 1.5.0, 1.7.2, 1.8.0, 1.9.0 and 1.10.0 routers
  with 1.10.1 clients (the eclipse/zenoh images), 1.7.2, 1.8.0 and 1.9.0
  routers with the clients built from the same release, 1.10.0 and 1.9.0
  routers with older clients (1.0.2, 1.3.4, 1.4.0, 1.5.0 and 1.6.2 against
  1.10.0 as well), 1.0.2, 1.1.1, 1.2.1, 1.3.4, 1.4.0, 1.5.0 and 1.6.2 routers
  with clients of their own release (built from the tags), zenoh-pico 1.10.1
  clients,
  240 short sessions captured for their handshakes, links that drop 1%, 5%,
  10% and 20% of the packets each way (UDP; TCP at 1% and 5%), that reorder
  a quarter of them or duplicate 5% (TCP and UDP), a real
  link between two machines (an office Wi-Fi: TCP with small and 3000-byte
  samples, joined mid-session, UDP, and zenoh-pico), and a real tunnelled
  path with twenty publishers (TCP and UDP);
- the `yes` sum's null chance of an outcome is the largest such upper bound
  over the null protocols (a unit read whole: mDNS, 13 of 36 units, bound
  0.51; a framing held: PostgreSQL, 0 of 48 directions, bound 0.060);
- the `no` sum's is the average over the null protocols of each one's
  Jeffreys estimate, `(k + 1/2) / (n + K/2)`, a proper distribution.

| outcome | `yes` sum | `no` sum | model 1 |
|---|---|---|---|
| unit read whole | +966 | +3546 | +2603 |
| unit residual | -13448 | -12029 | -6745 |
| unit undecoded | -13448 | -12559 | -7000 |
| stream framing held | +2836 | +6451 | (none) |
| stream framing lost | -7255 | -7238 | (none) |
| cookie matched (8 bytes) | +63991 | +63991 | +63999 |
| cookie differing | -7267 | -7267 | -10000 |
| Inits of opposite kinds | +991 | +991 | +999 |
| Inits of one kind | -6274 | -6274 | -9000 |
| version of this reader | +7995 | +7995 | +8000 |
| another version | -8266 | -8266 | (none) |

The unit weight fell because the corpus's real mDNS reads a unit whole 36% of
the time where the generated mDNS model 1 was priced on did 16%: model 1's
weight claimed more than the bytes give, against a protocol the corpus holds.
The handshake violations weigh less than model 1's assumed `2^-10` gave them:
about 300 clean handshakes bound a failure only to about 1.0%, and a weight may
not claim more than the corpus shows.

**The SN steps stay assumed, as a tolerance.** How often a step breaks is a
property of the link, what it loses and reorders, and not of zenoh: the
loopback and Wi-Fi captures break nothing in 940 steps, and a UDP link that
drops a share of the packets each way breaks about that share of its steps:

| link drops, each way | steps broken | flows (yes / no / undecided) |
|---|---|---|
| 1% | 4 of 230 (1.7%) | 2 / 0 / 0 |
| 5% | 6 of 110 (5.5%) | 2 / 0 / 0 |
| 10% | 0 of 2 | 2 / 0 / 0 |
| 20% | 17 of 94 (18%) | 8 / 0 / 2 |

The same was done to UDP and TCP with a link that duplicates 5% of the packets
or lets a quarter of them overtake the rest (netem, with a delay of 1.5 s: with
10 ms, which the first reordering captures used, a publisher that sends once a
second never has two packets close enough to overtake, and those captures broke
0 of 236 steps; they are not kept), and to TCP at 1% and 5% loss:

| link | steps broken | flows (yes / no / undecided) |
|---|---|---|
| UDP, 5% duplicated | 13 of 251 (5.2%) | 2 / 0 / 0 |
| UDP, 25% reordered | 28 of 211 (13%) | 2 / 0 / 0 |
| TCP, 1% lost | 0 of 238 | 2 / 0 / 0 |
| TCP, 5% lost | 0 of 239 | 2 / 0 / 0 |
| TCP, 5% duplicated | 0 of 239 | 2 / 0 / 0 |
| TCP, 25% reordered | 0 of 1 | 2 / 0 / 0 |
| TCP, delay 100 ms plus or minus 90 ms, 20 publishers | 0 of 4693 | 21 / 0 / 0 |
| UDP, the same | 1756 of 4684 (37.5%) | 21 / 0 / 0 |

A duplicated datagram repeats an SN and breaks the step at about the rate it is
duplicated, and a reordered one breaks the step it arrives out of; TCP hands
the stream to zenoh in order whatever the link does, so its steps never break.
The reordered TCP session carried one step in two minutes (99 units); with a
delay of 1.5 s each way it got little done, and why was not traced.

A link whose delay varies from packet to packet (100 ms plus or minus 90 ms
each way, with twenty publishers so that packets are close enough to overtake)
gives a TCP session that does carry steps: 979 of its 11783 packets arrived out
of order, 230 were retransmissions and 457 duplicate acknowledgements, and none
of its 4693 SN steps broke. Over UDP the same link broke 1756 of 4684 (37.5%),
and the 21 flows still read `yes`: the steps that follow are 62.5%, against the
third needed. The subscriber was delivered 1114 of about 2360 samples. A first
UDP run with the delay on from the start delivered nothing: the subscriber's
declaration arrived out of order, was dropped, and without a subscription the
publishers sent almost nothing (3 SN steps in the capture). The run kept puts
the subscription up on a clean link and adds the delay after. That the first
run went that way is inferred from its logs and its few frames, not from a
trace of the declaration.

A rate measured on any of them would describe that capture's link. The assumed
`2^-4` is the loss the test is built to tolerate, and it is not where the
verdict gives out. The SN steps alone push the `yes` sum up while the steps
that follow are more than a third of all, `f * 7907 > (1 - f) * 3994`, so a
link breaking up to two steps in three still reads `yes`; the 20% link, which
breaks 18%, does. What gives out first on a lossy link is the session, not
the verdict: the 10% capture holds two sessions that carried 2 steps between
them in two minutes, the 20% capture ten flows of which two read `undecided`,
and at 40% the handshake never got past the first Init and InitAck in two
minutes (11 packets, no session, not kept in the corpus).

Why was read from the logs of eight more runs, four at 10% and four at 20%
(150 s, the router and both clients at debug level, not kept in the corpus).
Of the 16 clients, 9 never opened a session: 8 waited out the 10 s open
deadline (`Unable to connect ... deadline has elapsed`) and one received a
KeepAlive where it expected the OpenAck and gave up at once (`Received an
invalid message in response to an OpenSyn`); the examples unwrap the open and
exit. The handshake is four datagrams that UDP does not resend, so it survives
a link dropping 10% each way with chance 0.9^4 = 66% and one dropping 20% with
0.8^4 = 41%; 4 of 8 and 3 of 8 opened. A session that is open ends when one
side hears nothing for the 10 s lease (`RX task failed ... expired after 10000
milliseconds`): in two of the four runs at 20%, in run 1 at 96 s on the
router and in run 2 at 48 s on the publisher, which reconnected and lost its
session again at 136 s, and in none of the four runs at 10%. Four of the 7 sessions that
opened also lost a message that zenoh sends as reliable and UDP does not
resend: an interest never answered with its DeclareFinal timed out after
10 s. A reconnect after a lease expiry meets the same handshake. The 10%
capture of the corpus ended in a new handshake after 110 s, three router
KeepAlives in a row missing before it, which fits the lease; the packets of
that capture alone do not say it.

A frame that repeats its SN never counts toward `yes`: a unit read whole
(+966) and a broken step (-3994) sum to -3028. On the `no` sum the two largely
cancel (+3546 and -3994: the null side reads a unit whole about one time in
twelve and a step breaks nearly always, a zenoh flow breaks a step one time in
sixteen), a frame that does both being 1.4 times as likely under the null as
under zenoh. A flow of such frames is never read `yes` and leans, slowly,
toward `no`.

**`stream_framing`.** A stream direction is judged once, by what happened
first: a unit framed (held) or a desynchronisation this reader inferred
(lost); a hole the capture reported judges nothing
(`PassiveSession::first_framing`). It is weighed only for a TCP direction the
capture holds from its SYN: a tap that joins a zenoh stream later lands inside
a unit nearly always and loses the framing too, so there the observation says
how the capture began and not what the bytes are. Held from the start, zenoh
never lost it (0 in 386). The forty short MQTT connections lose it in both
directions and read `undecided` still: twenty-odd bytes a direction are too
few to say `no` at 2^-20, and that is the honest word.

What moved on the corpus: no zenoh flow and no other flow changed word; every
new zenoh flow reads `yes`. Of the repository's own captures, the seven-unit
raweth capture moved from `yes` to `undecided`: a version header, seven units
read whole and one SN break come to about ten and a half bits, and model 1's
crossing rested on the unit weight the real mDNS beats.

Every zenoh capture added since (the links above and the releases below) moved
the counts and with them the weights, and the null captures moved with them. A
residual or undecoded unit now weighs -13448 on the `yes` sum, and -12029 or
-12559 on the `no` sum: two units that no codec of this reader reads whole
weigh -24058 or more there, past the threshold, where three were needed at
first (and two undecoded ones, but not two residual ones, after the SSH
capture). So a flow of two such units, and nothing else weighed, reads `no`.
`lan-dns` went from 2 `no` and 185 `undecided` to 174 `no` and 13 `undecided`,
`stack-coap` from 5 `no` and 20 `undecided` to 25 `no`, `lan-ssdp` from 1 and
1 to 2 `no`, and `busylan-ntp` from 94 `undecided` to 89 `no` and 5
`undecided`. No flow of another protocol read `yes`, and no zenoh flow read
`no`, before or after.

**Clients of the router's release.** Until now the clients were all 1.10.1,
and a router of another release was the only thing that varied. The `z_pub`
and `z_sub` examples were built from the 1.7.2, 1.8.0 and 1.9.0 tags and each
pair was captured against the eclipse/zenoh image of the same release, over
TCP and over UDP, on a link that loses nothing. All six captures read two
`yes` flows, and none of their 686 SN steps broke (114 or 115 a capture). The
counts grew by 1040 units, 12 handshakes and 12 framing directions, and the
weights of the failures moved by up to 228 millibits.

**Clients older than the router.** Six more pairs put a client and a router of
different releases together, the same way: 1.7.2 clients against a 1.10.0
router and against a 1.9.0 router, and 1.9.0 clients against a 1.10.0 router,
over TCP and over UDP. (The reverse, a 1.10.1 client against an older router,
was in the corpus already.) Every session opened, all six captures read two
`yes` flows, and none of their 685 SN steps broke. They add 1039 units and 12
handshakes: the weights of the failures moved by up to 197 millibits, and
three confirming ones by one millibit each (the cookie's fidelity -14 to -13,
the Init roles +986 to +987, a unit read whole +965 to +966), which moves the
example sums of the session table, of the C header and of the C consumer by 1
to 11 millibits.

**A real path.** The loss, reordering and duplication above are emulated.
This one is not: a zenohd 1.10.1 router on the build host, and on the host
here one subscriber and twenty publishers, each putting once a second (so that
the datagrams are closer together than the path's jitter), for two minutes,
over TCP and over UDP. The path is this host's Wi-Fi and the Tailscale tunnel
to the build host, and the capture is taken inside the tunnel, where the
interface gives raw IP frames; a fixed Ethernet header was put before each so
that the anonymiser and the reader take them, and nothing else was changed.
300 pings over that path lost none and took 2.7 to 178 ms (standard deviation
48 ms). All 21 flows of each capture read `yes`. Over TCP none of 3723 SN
steps broke. Over UDP 274 of 3510 (7.8%) did, which is more than the `2^-4`
(6.25%) the model assumes for a zenoh flow, and the verdict held: the steps that
follow are 92% of all, against the third needed. Which of reordering,
repetition and loss broke them was not traced; the capture inside the tunnel
cannot tell the tunnel's from the Wi-Fi's. The two captures add 9503 units and
42 handshakes.

**Older releases.** Router and clients of 1.0.2, 1.1.1, 1.2.1, 1.3.4, 1.4.0,
1.5.0 and 1.6.2 were built from their tags (no image of those was at hand, so
the router is built too; those of 1.0.2, 1.1.1 and 1.2.1 start only with their
rest plugin switched off, since they require the plugin otherwise) and captured
over TCP and over UDP on a link that loses nothing. All fourteen read two `yes`
flows and none of their 1599 SN steps broke. They add 2425 units and 28
handshakes.

**Older clients, further back.** The clients of 1.0.2, 1.3.4, 1.4.0, 1.5.0 and
1.6.2 against the 1.10.0 router, over TCP and UDP: ten captures, two `yes`
flows each, none of 1145 SN steps broke, and 1735 units and 20 handshakes more.
With the 1.7.2 and 1.9.0 pairs of the section above, a client older than its
router is held for seven releases. The corpus now holds routers of 1.0.2,
1.1.1, 1.2.1, 1.3.4, 1.4.0, 1.5.0, 1.6.2, 1.7.2, 1.8.0, 1.9.0, 1.10.0 and
1.10.1.

Still open after model 2: the other patch releases (1.0.0, 1.0.1, 1.1.0, 1.2.0,
1.3.0 to 1.3.3, 1.4.1 and the like) and 1.10.2, which the repository's
reference has moved to while every client in the corpus is 1.10.1 or older; a
client older than its router for 1.8.0; a link that really loses packets (the
tunnelled path lost none in 300 pings, and broke steps only over UDP); and the
null side only on the protocols the corpus holds.
