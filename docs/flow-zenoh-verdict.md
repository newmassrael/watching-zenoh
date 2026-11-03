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
  and 0 undecoded in 49505 units; 0 framings lost in 584 directions held from
  their start; 0 differing cookies in 609 echoes; 0 Init pairs of one kind in
  611; 0 other versions in 1222 version headers. The zenoh files are 1.10.1
  routers and clients, upstream 1.5.0, 1.7.2, 1.8.0, 1.9.0 and 1.10.0 routers
  with 1.10.1 clients (the eclipse/zenoh images), 1.7.2, 1.8.0 and 1.9.0
  routers with the clients built from the same release, 1.10.0 and 1.9.0
  routers with older clients (1.0.2, 1.3.4, 1.4.0, 1.5.0 and 1.6.2 against
  1.10.0 as well), every plain 1.x release from 1.0.0 to 1.10.2 with clients
  of its own release (1.7.2, 1.8.0 and 1.9.0 against the
  eclipse/zenoh images, the others against routers built from the tags), a
  1.10.2 client against routers of 1.0.2, 1.3.4, 1.5.0, 1.6.2, 1.7.2, 1.8.0,
  1.9.0 and 1.10.0 and a 1.10.1 one against a 1.10.2 router, zenoh-pico 1.10.1
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
| unit read whole | +967 | +3546 | +2603 |
| unit residual | -14012 | -12594 | -6745 |
| unit undecoded | -14012 | -13124 | -7000 |
| stream framing held | +2838 | +6453 | (none) |
| stream framing lost | -7611 | -7594 | (none) |
| cookie matched (8 bytes) | +63993 | +63993 | +63999 |
| cookie differing | -7671 | -7671 | -10000 |
| Inits of opposite kinds | +993 | +993 | +999 |
| Inits of one kind | -6676 | -6676 | -9000 |
| version of this reader | +7996 | +7996 | +8000 |
| another version | -8668 | -8668 | (none) |

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
(+967) and a broken step (-3994) sum to -3027. On the `no` sum the two largely
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
crossing rested on the unit weight the real mDNS beats. Since a JOIN states
where its sender's SNs start on a link with no handshake (2026-11-02), that step
is no break: the capture's Fragment carries the SN its JOIN names next, the step
follows, and the capture reads `yes` under model 2 as well.

Every zenoh capture added since (the links above and the releases below) moved
the counts and with them the weights, and the null captures moved with them. A
residual or undecoded unit now weighs -14012 on the `yes` sum, and -12594 or
-13124 on the `no` sum: two units that no codec of this reader reads whole
weigh -25188 or more there, past the threshold, where three were needed at
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

**1.10.2 and more patch releases.** The repository's reference has moved to
1.10.2, so router and clients of 1.10.2 were captured, and a 1.10.2 client
against the 1.10.0 router, and a 1.10.1 client against a 1.10.2 router. Router
and clients of 1.0.0, 1.0.1, 1.1.0, 1.2.0, 1.3.0 and 1.6.1 were built from
their tags as the others were (those up to 1.2.0 start only with the rest
plugin switched off), and a 1.8.0 client was put against the 1.10.0 router.
Twenty captures, two `yes` flows each, none of their 2298 SN steps broke; they
add 3575 units and 40 handshakes. 1.0.0 puts about 220 units into its minute
where the others put about 173. The extra units are KeepAlives: 1.0.0's
transport task sends one on a fixed period on every session, whatever else it
sends (the transmit loop of the unicast link in the `zenoh-transport` crate at
the 1.0.0 tag selects on a timer that ticks every period), and 1.0.1 sends one
only after the period has passed with nothing sent (the same loop at the 1.0.1
tag wraps its pull of the next batch in a timeout of one period and sends the
KeepAlive when it fires). Those are two tags older than the pin, so they are
read here and not cited as the pin's lines. In the UDP minute that is 94
datagrams of 9 bytes against 46, and the 48 between them are the 48 datagrams
by which the two captures differ. A KeepAlive carries no SN, so the SN steps
are the same in both (115 against 114).

**More patch releases, and clients newer than the router.** Router and clients
of 1.3.1, 1.3.2, 1.3.3, 1.6.0, 1.7.0 and 1.7.1 were built from their tags
(twelve captures), and the 1.10.2 client was put against the eclipse/zenoh
1.9.0, 1.8.0 and 1.7.2 routers (six captures: a client two to four releases
newer than its router). All eighteen read two `yes` flows, and none of their
2055 SN steps broke. They add 3117 units and 36 handshakes.

**A path that really loses.** The tunnelled UDP capture of the section above
was taken again with a paced UDP load of 150 Mbit/s from the client host to
the build host for the same two minutes. The load was found first, in steps of
ten seconds from 10 Mbit/s: pings lost nothing at any step up to the ceiling
set for it, 150 Mbit/s, where 101 of 156250 datagrams (0.065%) did not
arrive. Held for two minutes, 150 Mbit/s lost 32246 of 1750000 datagrams
(1.84%) and 500 pings lost 1.6% (their time was 100 s). The zenoh sessions
stayed up and the subscriber was delivered 2292 samples. The 21 flows read
`yes`, and 332 of 3331 SN steps broke (10.0%), against 7.8% on the unloaded
path: the loss adds about two points to what the path's jitter already
breaks, and the step of the verdict is far from giving out (the steps that
follow are 90%). The load stopped at the ceiling; a path losing more than
this one was not tried, because making it lose means pressing a network that
other people use.

**The last four tags, and clients ten minor lines newer.** Four plain 1.x
release tags were not yet in the corpus: 1.0.3, 1.0.4, 1.2.3 and 1.5.1. Router
and clients of each were built from the tag and captured, so every plain 1.x
release tag (29 of them, 1.0.0 to 1.10.2) now has a router in the corpus, and
all of them but 1.10.0 clients of their own release (see the next paragraph for 1.10.0). And the 1.10.2 client was
put against routers built from the 1.6.2, 1.5.0,
1.3.4 and 1.0.2 tags: a client four, five, seven and ten minor lines newer than
its router. All sixteen captures read two `yes` flows and none of their 1830 SN
steps broke. They add 2774 units and 32 handshakes.

**1.10.0 beside its own router.** The one plain release left was 1.10.0:
`z_pub` and `z_sub` built from its tag were put against the eclipse/zenoh
1.10.0 router, over TCP and UDP. Both captures read two `yes` flows and none
of their 114 SN steps broke. With them all 29 plain 1.x release tags have a
router and clients of their own release in the corpus. They add 346 units, 4
handshakes, and the weights above.

**Release candidates.** Of the tags that are not plain releases, the two
latest of the 1.0.0 line were built and captured as the plain ones were:
1.0.0-rc.1 and 1.0.0-rc.2, router and clients of one tag, over TCP and UDP.
All four read two `yes` flows and none of their 459 SN steps broke, so a
release candidate of the 1.0.0 line speaks the wire this reader reads. They
add 881 units and 8 handshakes.

**Beta and alpha.** The latest beta and the latest alpha of the same line,
1.0.0-beta.4 and 1.0.0-alpha.6, were built and captured the same way. All four
captures read two `yes` flows and none of their 460 SN steps broke: the wire of
the 1.0.0 line did not change between alpha.6 and the release, as far as this
reader looks. They add 880 units and 8 handshakes, and a unit read whole
weighs one millibit more on the `yes` sum (+967), which moves the example sums
of the session table, of the C header and of the C consumer by 3 to 10
millibits.

Still open after model 2: the other alpha and beta tags of 1.0.0 (alpha.2,
alpha.4, alpha.5, beta.1 to beta.3) and the 0.x tags, whose wire may differ,
which makes the 0.x tags a test of the foreign version weight and not of the
`yes` side,
a path that loses more than 1.8%, and the null side only on the protocols the
corpus holds.

### 6.3 The calibration judged by group (2026-11-01)

The corpus test reads every file with weights counted from every file. That is a
fit, and a protocol that is in the null family sets the family's largest chance
of an outcome, so its own flows are weighed against a bound it helped to make.
Nor are the counts what they look like: the units of one session share a stack,
a generator and a link, so 49505 units are not 49505 independent trials. What is
independent is a capture, and better a group of them: a null protocol, a zenoh
release line, a link condition.

`crates/wz-capture/src/zenoh_calibration_tests.rs` (in the build that opens lz4)
holds three things. A flow's two sums are linear in its outcome counts, and the
first test shows the shipped weights applied to the counts give back every
flow's own sums, and the second that the fit it uses counts the shipped weights
from the whole corpus; so the rest reads the library and not a look-alike. The
third leaves one group out at a time, counts the weights again from the others
and reads the left-out flows with them (40 groups: 18 null protocols, 22 zenoh
groups by release line, link and what the file exercises, named in the `groups`
of the manifest, where a file in no group or in two stops the reader). It prints, and asserts nothing about the
rates, because the owner has not said what the corpus must show.

What it shows:

- **No flow changes its word when its group is left out**, in 40 groups. The
  extreme sum (the lowest `yes` sum of a zenoh group, the highest of a null one)
  moves by 2.4 bits at most (the jitter group, 38597 to 36194) and mostly by
  under 0.2. The closest a null flow comes to `yes` is a DNS flow at +1934, 18
  bits short; the lowest `yes` of a zenoh group that reaches it is the jitter
  group's, 16 bits over. The 20% loss group already holds two zenoh flows that
  stay `undecided`.
- **The failure chances stand on far fewer things than their bounds say.** All
  zenoh failures are zero, and the one-sided 95% bound on each is 6.1e-5 on the
  49505 units (the weight of a residual unit), 0.0212 on the 140 files and
  0.1273 on the 22 groups; for framing lost, cookie, roles and version on their
  own counts of 584 to 1222 it is 0.0024 to 0.0051 on the units and the same
  0.0212 and 0.1273 on files and groups. The weights use the first.

What it cannot show is what matters most. No group has a failure, so leaving
one out cannot say what a failure in a group not yet captured would do, and the
weights say it is a 14-bit event: two residual units weigh -25188 on the `no`
sum, past the threshold, so a zenoh workload this reader reads badly, with a
message kind it does not decode, reads `no` after two such units. The corpus
holds one traffic generator and eleven release lines of the same code; queries
and replies, liveliness, fragmented payloads, other priorities, authentication
and another implementation are not in it. How often an unseen group fails a unit
is the open number, and the group bound of 0.1273 is the honest statement of
how little the corpus says about it.
The next steps are in that direction, not toward more release tags (all of
which read alike): a model in which a group has its own failure rate (a
Beta-binomial over units, so a flow's evidence for zenoh saturates instead of
growing by 967 for each unit), the SN break rate as a mixture and not a
constant, workload groups in the corpus, and a held-out set the weights are
never counted from.

The calibration is not written by hand any more. `zenoh_calibration_generated.rs`
holds the counts of the corpus and the weights computed from them, and the test
`the_generated_calibration_is_current` renders it from the corpus and fails with
the first line that differs; `scripts/regen-calibration.sh` writes it. A capture
added to the corpus is then a manifest entry, its line in a group, and that one
command, where it was the counts, twelve weights and a dozen pinned numbers by
hand. The same test holds this note's weight table and its counts to the
calibration. What it does not move: the example sums that the session table, the
C header and the C consumer pin (a test names each when it no longer matches),
and the SN steps' weights, which are assumed and not counted. The command is not
a `bx` action: an action's output must lie outside what the `regen-codegen` action
reads, which is every file, and the two would be a cycle, so on a build machine
the failing test prints the file and that text is the file. A control showed the
test does its work: one count changed by one in the generated file fails it, the
corpus's own count test and the weights' derivation test.

### 6.4 What the corpus must show: the acceptance criteria (2026-11-01)

The thresholds are `alpha = beta = 2^-20`, about one in a million. A corpus
cannot measure a rate that small: with no failure seen in `n` independent
trials the one-sided 95% bound is about `3 / n`, so one in a million needs about
three million independent flows, and the corpus holds hundreds. Asking the
corpus to show the nominal rate would fail the test for the wrong reason, or
pass it by a count of units that are not independent. The claim is therefore
made in three layers, each checked by what can check it.

1. **The theory** guarantees the nominal rate when the model is true: Ville's
   inequality (section 2) bounds the chance that `2^L` ever reaches `1/alpha`.
   That is a proof, and nothing in the corpus tests it.
2. **The model's validity**, which is what the corpus can test. The model is true
   when each increment is a conditional likelihood ratio, and the way it fails is
   that a group of captures behaves unlike the ones the weights were counted
   from. It is tested at levels the corpus can reach: the same sums are read
   against the thresholds `2^-1` to `2^-10` (`+1` to `+10` bits and the same
   below), and the share of independent GROUPS that cross each one is held to
   the level, with its exact interval. If the shares fall as the levels do, the
   rate at `2^-20` is an extrapolation from a model that held where it could be
   seen, and is stated as one.
3. **The operating characteristics**: how many units a flow needs before the
   verdict is read (Wald's expected sample size and its 95th percentile), per
   protocol and per group.

**Independence is counted in groups.** A group is a null protocol, a zenoh
release line, a link condition or a workload (section 6.3), and with no failure
seen in `G` groups the one-sided 95% bound on a group failing is
`1 - 0.05^(1/G)`. The two errors are counted on different groups: the false `no`
over the zenoh groups and the false `yes` over the null ones. The numbers below
are the recommendation of this session, to be stated and moved only by a ledger
entry:

| level of the claim | a group fails with chance at most | independent groups needed (each side) | zenoh groups held | null groups held |
|---|---|---|---|---|
| interim | 10% | 29 | 22 | 18 |
| first target | 5% | 59 | 22 | 18 |
| final target | 1% | 299 | 22 | 18 |

The interim row is the first one the corpus can reach by adding captures of the
kinds it lacks. Counting the groups is not the same as covering the workload: a
group is only independent evidence if it differs in what can make the reader
fail, and 22 zenoh groups of one traffic generator are fewer than they look. The
groups that count are the ones section 6.3 lists as absent: queries and replies,
liveliness, fragmented payloads, other priorities, authentication, multicast and
an implementation other than the reference one.

**Two corpora, one frozen.** The development corpus is what exists; it chooses
the model by leaving a group out (section 6.3). A validation corpus is collected
AFTER the model is frozen, of implementations, workloads and links the model was
not fitted on, and is not counted into any weight until it has been reported
once. The weights, the groups' definition and the thresholds are fixed by a ledger
entry before the first of its files is read, which is what a pre-registration is
for.

**What this section does not decide.** The levels of the table are the
recommendation of this session, not a ruling; the model that makes the
extrapolation honest (a failure rate per group, a Beta-binomial over units, so a
flow's evidence saturates and the width of the prior follows the number of
groups), the time order of a flow's evidence that the second layer needs (the
reader reports a sum today, and the running maximum is the quantity Ville bounds),
and the consumer's field for the model version and the level the evidence
supports are each a step with its own entry, the last two with the consumer.

### 6.5 A candidate for the unit reading: a failure rate per group (2026-11-01)

The shipped model gives every unit of a zenoh flow the same chance of failing,
the bound the corpus allows, and adds the units up: `n` units weigh `n` times
one unit, and a failure always costs the same. That is a model of one population
of units. The corpus has 22 zenoh groups, and the units of a group share what
makes them read well or badly.

`crates/wz-capture/src/zenoh_hierarchy_tests.rs` held a candidate (until model 3
shipped, section 6.8, which removed the report). Each group has its own failure rate, drawn from
a Beta distribution whose mean has the Jeffreys prior and the posterior the 22
groups give it, none of which failed a unit, and whose spread is a
concentration `kappa`: a Beta-binomial over the units of a group. A flow of `n`
units, `k` of which failed, weighs the log of its probability under that
predictive against the shipped null side, so that only the zenoh side moves.

`kappa` is the number the corpus cannot give: with no group failing, how unlike
each other the groups' rates are is not measured. The report therefore reads the
corpus at several, and what it answers is how much of the shipped verdict rests
on the choice.

- **With the null side as the shipped one, the zenoh side does not move at any
  `kappa`**: 619 flows `yes` and 2
  `undecided` (the two of the 20% loss link), 0 `no`. No flow with no failed
  unit changed its word. At `kappa` = 10^6, where the groups are alike, the
  candidate reads the corpus exactly as the shipped model does, and the weight
  of a flow with no failure differs from it by under 0.1% (+38648 against +38680
  for 40 units).
- **What moves is the `no` of the null flows.** Of 653 null flows the shipped
  model reads 345 `no` and 308 `undecided`. The candidate reads 54 `no` at
  `kappa` = 16 and 5 at `kappa` = 1. DNS, NTP, CoAP, DHCP and the rest go back
  to `undecided`: their units fail, and the shipped model prices a failing unit
  of a zenoh flow as a rare event, so a run of them is conclusive. A model that
  admits a zenoh group whose units fail most of the time does not call a flow
  not zenoh for that alone.
- **The same holds for flows in which every unit failed**: 10 units read `no` at
  `kappa` >= 16 and `undecided` below; 40 units read `no` from `kappa` = 4; 2
  units read `no` only at `kappa` = 10^6. The shipped model says `no` at 2.

That the candidate loses `no` is partly its own doing, and the report shows how:
at `kappa` = 1 a flow of 531 units that all failed weighs +51235 on the `no` sum,
toward zenoh. The candidate makes the zenoh side heterogeneous and leaves the
null side as independent units, which fail with a fixed share. A heavy-tailed
zenoh side then beats a null side that falls off geometrically, as the run
lengthens. The null side was then made heterogeneous too (below), which is the
measurement of what was here an argument.

#### With the null side heterogeneous too

Each null protocol is a Beta-binomial over the units of its flows: the share of
its units that fail is its own, and so is the spread among its flows, estimated
from them by the concentration of a grid that makes them likeliest (a member
with fewer than 5 flows that framed a unit has none estimated, and takes a spread
of 1 on the `yes` sum and independent units on the `no` sum, each the cautious
side for the error it could cause). The estimates differ a great deal: DNS, RTPS,
CoAP and SOME/IP at 0.05, the grid's floor and the most heterogeneous it allows
(so the true spread may be smaller still), DHCP at 1, mDNS at 2, NTP and WSD at
10000, the grid's ceiling, which is independent units. Five members have no
estimate (SSDP, MQTT, QUIC, PostgreSQL and SSH), and five more framed no unit and
are not members of this model.

- **The sign of the artifact is gone and the `no` is not back.** A flow of 531
  units that all failed weighs -15975 on the `no` sum at `kappa` = 1, where it
  was +51235, so the null side's heavy tail does what the argument said. But it
  stays short of the threshold at `kappa` = 1, and reads `no` at `kappa` = 16 for
  10 units or more, as it did with the independent null. Of 653 null flows, 9
  read `no` at `kappa` = 1 and 55 at `kappa` = 16 (345 shipped, and 5 and 54 with
  the independent null). So the loss of `no` is the model's and not only the
  candidate's asymmetry: if zenoh groups can fail their units as the null's flows
  do, a run of failed units does not tell them apart. (`kappa` = 4 was read with
  the independent null only.)
- **A zenoh flow reads `no`.** One flow of `zenoh-jitter-udp-20pub.pcap`, at every
  `kappa` including 10^6, where the zenoh side is the shipped one. Its 2401 units
  all read whole; of its SN steps 588 followed and 1756 broke (75%, against the
  6% that `SN_BREAKS` assumes). The shipped model weighs its units +8513946 on the
  `no` sum and its SN steps about -2364148, and the flow reads `yes` at +38597,
  18 bits over the threshold, as the difference of two numbers of millions. With
  the null heterogeneous the units weigh +7907 (about 8 bits): 2401 units that
  read whole are not 2401 pieces of evidence when a null protocol's flows read
  whole all at once or not at all, and the evidence saturates, as it should. The
  SN steps stay at their sum, and the flow reads `no`.

That is the finding, and it is not a defect of the null side. The shipped model
sums two kinds of observation that are both strongly correlated within a flow, the
units and the SN steps, and the first sum was large enough to carry the second.
Making the first one honest exposes the second: an SN break rate that is a
constant, in a flow whose link breaks three steps in four. The break rate is a
property of the link, as the units' failure rate is of the group, and it belongs
in the model the same way (a mixture over the rate, so that a flow with many
breaks is a flow of a bad link and not a flow of many independent breaks). The
two are one step, and neither ships alone: the candidate with the units alone
turns a real zenoh flow into a false `no` (section 6.6 takes the second half).

What the measurements already say is where the shipped verdict stands. The 345
null flows that read `no` rest on `kappa` being large: on the groups of zenoh
being alike in how their units read. The corpus cannot say that, because no zenoh
group has failed a unit; it is measured by zenoh groups that do (workloads and
implementations this reader reads badly, which section 6.4 asks for for another
reason). And the `yes` of the jitter flow rests on the same independence
assumption, in the other direction: two sums of millions that nearly cancel.
Neither is a defect of a flow the corpus misreads today. Both are numbers that a
link or a workload the corpus lacks would move.

### 6.6 The SN steps as a mixture over the link's break rate (2026-11-02)

The shipped weights price every SN step alone: +7.907 bits for a step that
follows, -3.994 for one that breaks, which assumes the flow's link breaks one step
in sixteen. The corpus has links that break none, 8%, 10%, 37.5% and, in one
flow, 75% of them. That is a property of the link, and the steps of one flow share
it. The candidate (`zenoh_hierarchy_tests.rs`, nothing shipped) gives each flow a
break rate of its own, drawn from a Beta distribution whose mean and
concentration are the ones that make the corpus's zenoh flows likeliest (a grid
over both): mean 0.0044, concentration 2, which says most flows break nothing and
the tail is heavy. A flow weighs the log of its steps' probability under that
mixture against the null's, which is the shipped one (a step follows with chance
at most 2^-8, as a varint). Unlike the units' failure rate this one is measured,
since the corpus holds links that break steps.

| steps | shipped | mixture |
|---|---|---|
| 100 followed, 0 broke | 790700 | 799946 |
| 100 followed, 6 broke | 766736 | 759855 |
| 50 followed, 50 broke | 195650 | 290498 |
| 0 followed, 20 broke | -79880 | -15374 |
| 0 followed, 29 broke | -115826 | -16369 |
| 588 followed, 1756 broke | -2364148 | +2795271 |

A break costs what the rate of its link says and not 4 bits: a flow of breaks
alone is a flow of a bad link, which the shipped model prices as 29 independent
rare events. A followed step still weighs about 8 bits, the null's chance of a
varint equal to the last plus one, and that is what the 588 followed steps of the
jitter flow are worth.

Every zenoh flow was read with the prior fitted WITHOUT its own group (22
fits), and the fit without the jitter group is the fit with it (the same grid
point), so the jitter flow is judged by a prior that has not seen it.

- **The false `no` of section 6.5 is gone.** With the SN mixture and the
  candidate units, 619 zenoh flows read `yes`, 2 `undecided` (the two of the 20%
  loss link, as shipped) and none `no`, at every `kappa` and with the null side
  heterogeneous too. The jitter flow reads `yes` again.
- **With the shipped units the SN mixture moves no word**, in zenoh flows or null
  ones: the null flows that read `no` rest on their units.
- **The null `no` is as in 6.5**: 345 shipped, 7 at `kappa` = 1, 54 at 16, 345 at
  10^6. No null flow reads `yes` under any variant.

What this does not settle:

- The prior is a maximum-likelihood point estimate from about 640 flows, not a
  posterior, and the 75% flow is the only one of its kind in the tail it shapes.
  A link breaking 90% of its steps is a link the corpus has not seen.
- The null side of the steps is still derived and not measured: a flow of a null
  protocol with a counter in its frames would follow often. The corpus has none
  that parse as frames.
- The arithmetic it needs now exists and is checked (`zenoh_mixture.rs`; model 3
  reads the same mixture one step at a time, section 6.8). The crate is `no_std`, with no third-party dependency
  and no float maths outside its tests, and the weights are integers a C header
  pins to the unit, so the mixture is computed in integers. The Beta parameters
  are fractions of one denominator, so that a rising factorial is a product of
  integers over it and its logarithm is the logarithm of an integer; that
  logarithm is found to 64 fractional bits by squaring a 128-bit mantissa
  (`log2_q64`, exact for the powers of two and within 10^-12 bits of the
  floating-point logarithm elsewhere); a rising factorial of many factors is a
  ratio of gamma functions, taken by shifting the argument up to 16 and
  finishing with Stirling's series, so the cost does not grow with the steps a
  flow holds. Tests hold it to a direct floating-point sum over three priors and
  64 step counts (within the rounding), to the rising factorial for arguments
  either side of the point where Stirling takes over and up to 10^5 factors
  (within 3 * 10^-9 bits), and to eleven values computed apart from it, to the
  unit. Counts above 2^36 are counted as 2^36. What is left is not arithmetic:
  the prior as parameters (88 / 19912 over 10000 is the fit rounded; a generated
  constant, like the rest of the calibration), `sn_steps_weight` taking the
  mixture in place of the two constants it multiplies, the pinned examples that
  move with it, and the model number.
- Together with the units of section 6.5 it changes what a consumer sees: null
  flows that read `no` read `undecided`. The zenoh words do not change. The
  zenoh-analyzer session reads that.

### 6.7 The rule of model 3, and the decisions behind it (2026-11-02)

The owner left these decisions to this session on 2026-11-02, with one
criterion: the structure that is right in the long term and stands in the
textbooks, whatever it costs. They are recorded as decisions, each with its
reason, and a ledger entry moves them.

**D1. Each sum is an e-process against the hypothesis it rejects.** The `yes`
sum rejects the null and the `no` sum rejects zenoh (section 2). Each hypothesis
is composite: it leaves rates unknown. What the REJECTED hypothesis leaves
unknown is taken at its likeliest over what the corpus allows of it, the
region of its parameters at 95%; what the OTHER hypothesis leaves unknown is
mixed over a prior. That is universal inference (Wasserman, Ramdas and
Balakrishnan, 2020) inside the frame of testing by betting (Ramdas, Grünwald,
Vovk and Shafer, 2023): for every member `p` of the rejected hypothesis, the
ratio against its likeliest member is at most the ratio against `p`, which is a
martingale under `p`, so Ville's bound holds at every moment whatever `p` is.
The prior on the other side moves only how soon a word is reached, never the
chance that it is wrong, so it may be fitted on the corpus freely. Model 2
already follows the rule for single outcomes (the `yes` sum's largest null
probability, the `no` sum's upper bound on a zenoh failure); what it does not
follow is that the outcomes of one flow share a rate. Sections 6.5 and 6.6 are
that defect, and D1 is its repair.

- A zenoh failure rate (units, framing, cookie echo, Init roles, version) is a
  property of zenoh, of its release, implementation and workload, so it is a
  rate per GROUP (section 6.3) with a Beta spread. On the `no` sum it is taken
  at its likeliest over the concentrations from all-or-nothing groups to
  independent outcomes, and over the means the 22 groups leave in their 95%
  region at each. The concentration the corpus cannot identify (section 6.5) is
  therefore not chosen: it is the worst case, which is what an unidentified
  nuisance of the rejected hypothesis must be.
- An SN break rate is a property of the LINK and not of zenoh, so the zenoh
  hypothesis does not restrict it: on the `no` sum the zenoh side takes the
  rate likeliest for the flow's own steps, and broken steps are never evidence
  against zenoh. On the `yes` sum the zenoh side mixes it over the prior of
  section 6.6.
- A null protocol's rates are its own (section 6.5), and on the `yes` sum they
  are taken at their likeliest over the members and the spreads.

**D2. The acceptance levels of section 6.4 are confirmed**: a group fails with
chance at most 10% (interim), 5% (first target), 1% (final target), shown by
29, 59 and 299 independent groups on each side. They are the levels at which
the second layer of section 6.4 is reported, and they move only by a ledger
entry.

**D3. Model 3 is the whole rule in one step.** Units, SN steps and the zenoh
side of the other checks change together, on both sums. The SN mixture alone
would move no word (section 6.6) and could ship sooner, but it is half a model:
the model is frozen once, before a validation corpus is read (D5), and two
consumer-visible model numbers for one rule would put a frozen state between
them that nothing tests. The integer arithmetic rounds every term TOWARD the
hypothesis its sum rejects (down for the `yes` sum, up for the `no` sum), so
that the integer e-process is never above the real one; rounding to the
nearest, which `zenoh_mixture.rs` and model 2's generated weights did, can raise a
sum by half a millibit per term, and a flow has thousands of terms.

**D4. The verdict latches at the first crossing, and the reader reports when.**
Ville's inequality bounds the chance that the process EVER crosses, so the word
of a flow is the first crossing and the moment of it, not the sum at the end;
the reader also reports the model number. Both change the consumer, and the
zenoh-analyzer session takes them with model 3. The shape agreed with it on
2026-11-02:

- The model number goes in the `model` key `zenoh_evidence` already has, as 3.
  No second key says the same thing.
- `zenoh_evidence` gains `crossed_at_packet`, the capture-global packet index (the
  axis of a row's `packet`, which the consumer joins rows on; a time can repeat
  and cannot) of the first crossing, `null` while no threshold has been crossed
  and for nothing else; and `log2_lr_max_millibits`, `log2_lr_min_millibits`,
  `log2_lr_no_max_millibits`, `log2_lr_no_min_millibits`, the extremes of each
  sum so far, in millibits like the sums.
- The side that crossed is not a key: the latched `zenoh` word is that side.
- `log2_lr_millibits` and `log2_lr_no_millibits` stay the sums NOW, not at the
  crossing, so a latched `yes` can stand beside a sum below the threshold. That
  is what the keys mean; how a consumer words it is the consumer's and moves
  nothing here.
- The keys move the `fields` and `session_table` documents one revision each
  (48 and 6 today), numbered when model 3 ships, and the numbers are told to the
  consumer then. Nothing in wz waits on the consumer's side of the change.

**D5. The model is frozen by a ledger entry before a validation corpus is
read**, and the validation corpus is evaluated once (section 6.4, two corpora).
The entry names the rule, the region level, the priors and the group
definition; the corpus is of the workloads, implementations and links section
6.4 lists as absent.

**D6. A `no` comes from recognising what the flow is.** Under D1 a flow whose
units fail is evidence against zenoh only as far as a new zenoh group could
fail them, which 22 groups bound at about 13%: a few bits, never twenty. The
`no` sum grows when its numerator is a model that reads the flow well, that is
when the flow is recognised as a null protocol and not only as a failed zenoh
reading. That is model 4: a likelihood per null protocol in the `no` sum's
numerator, in wz, as the frame wz extends past the zenoh presets.

**What the rule reads on the corpus**
(`the_corpus_read_by_the_rule_of_model_three`, a report in floating point that
was removed when model 3 shipped; section 6.8 has what the reader itself
reads). Every flow's units, SN steps and the zenoh side of its other checks are
replaced by the rule's; the checks are taken as independent within a zenoh
group, the generous side for `no`. The region's two ends are the bounds already
stated (`the_region_of_a_zenoh_failure_rate_ends_at_the_two_known_bounds`): at a
concentration of 10^-3 a group fails with chance at most 0.126 (the 22-group
bound 0.127), at 10^7 a unit fails with chance at most 6.05e-5 (the 49505-unit
bound).

| | `yes` | `no` | `undecided` |
|---|---|---|---|
| zenoh flows, model 2 | 619 | 0 | 2 |
| zenoh flows, the rule | 619 | 0 | 2 |
| null flows, model 2 | 0 | 345 | 308 |
| null flows, the rule | 0 | 0 | 653 |

- No zenoh word moves. The two `undecided` are the two flows of the 20% loss
  link, two units and a handshake without a cookie, as in model 2.
- Every null `no` goes: DNS 174, NTP 89, CoAP 25, DHCP 21, RTPS 9, WSD 8,
  SOME/IP 5, MQTT 4, PostgreSQL 3, and two or fewer from SSDP, QUIC, SSH and
  mDNS. No null flow reads `yes`.
- A flow whose units all failed weighs -2.8 bits on the `no` sum at 2 units and
  -1.7 at 531: the bound on a new group failing, and no more. A flow whose units
  all read whole weighs about 1.1 bits on the `yes` sum at 10 to 400 units, the
  units of a null protocol whose flows read whole all at once. The `yes` of a
  zenoh flow rests on the cookie echo and the SN steps that follow, whose null
  chances are derived from field widths.

So the 345 `no` of model 2 rest entirely on outcomes of one flow being
independent, and the corpus does not support that at `2^-20`. Model 3 reads
them `undecided` until model 4 recognises them (D6).

### 6.8 How model 3 is computed, and what it reads (2026-11-02)

Model 3 ships the rule of section 6.7: `model` reads 3, the field document
moves to revision 49 and the session table to revision 7. Implementing it took
two more decisions, recorded here with their reasons.

**D7. A row of a pair is a test of its own.** The test is of a flow's bytes. A
session row groups the flows whose handshakes named the same two nodes, and
which flows those are is learned from the bytes as they arrive. Adding a
flow's earlier sum to a row at the moment the flow names the pair is not a
step of a supermartingale (the value it brings is known when it is added), and
the packet that names the pair is selected by its own observations (an Init
names a node only out of a unit read whole). So a row's evidence is an
e-process over what its flows observe FROM THE PACKET AFTER each named the
pair: the group-rate checks as one stream (one implementation), the SN steps
per link (the break rate is the link's). A flow that comes to name another
pair stops adding to the first row there, which stops that part of the
process, and starts in the new row after that packet. A row of one flow that
names no pair is that flow's evidence. A row and its only flow can therefore
differ by the handshake's own observations; the cookie echo comes after the
InitAck and counts in both.

**D8. Every bound is computed in closed form, on the safe side.**

- The rejected hypothesis is taken outcome by outcome: each step multiplies by
  the largest PREDICTIVE chance any of its members gives the outcome after the
  flow's past. The product is at least the largest chance any member gives the
  whole sequence, so the e-process is below the one universal inference
  defines, and valid with it. Its forms:
  - a null member of a measured check (unit readings, stream framing), on the
    `yes` sum: the larger of the outcome's bound over the members (model 2's)
    and the flow's own share of it so far. A member's flows spread around its
    share with a concentration the corpus does not bound, and the predictive
    chance is an average of the two, largest at one end;
  - a zenoh failure rate (unit readings, stream framing, cookie echo, Init
    roles, version header), on the `no` sum: a success weighs nothing (a rate
    of zero is in every region), and a failure after `k` failures in `t`
    outcomes takes the largest `(k + kappa mu(kappa)) / (t + kappa)` over the
    region, `mu(kappa)` its top. `mu` falls as `kappa` grows, so a grid of eight
    concentrations a decade from 10^-3 to 10^7 bounds every cell, and the ends
    are the bounds on groups and on outcomes
    (`the_generated_regions_bound_every_concentration`);
  - the SN steps, on the `no` sum: the link's likeliest break rate for its steps
    so far, a function of the counts.
- The other hypothesis is mixed over a prior fixed before the flow: the SN
  steps over the Beta of section 6.6, fitted again on the corpus's links; each
  group-rate check over a prior of weight one outcome centred on the zenoh
  files' Jeffreys estimate; the measured nulls of the `no` sum over the
  members' average Jeffreys share, as in model 2.
- The arithmetic is in integers (`crates/wz-capture/src/zenoh_eprocess.rs`):
  logarithms to 64 fractional bits, each value carrying a bound on its error,
  and each check's part rounded to millibits toward the side its sum rejects
  past that bound. A sum is its checks' parts added. The word latches after the
  observation that first crosses a threshold, and the extremes include the
  starting zero.

The parameters are generated from the corpus with the counts
(`zenoh_calibration_generated.rs`, held by
`the_generated_calibration_is_current`):

| measured null | `yes` bound per outcome | `no` mean per outcome |
|---|---|---|
| unit readings | 5.1168e-1, 1.0000e0, 1.0000e0 | 8.5591e-2, 3.7417e-1, 5.4024e-1 |
| stream framing | 1.3911e-1, 1.0000e0 | 1.1353e-2, 9.8865e-1 |

| check | zenoh prior failure mean | region top as kappa goes to 0 | at 10^7 |
|---|---|---|---|
| unit readings | 2.0200e-5 | 1.2731e-1 | 6.0536e-5 |
| stream framing | 8.5470e-4 | 1.2731e-1 | 5.1166e-3 |
| cookie echo | 8.1967e-4 | 1.2731e-1 | 4.9070e-3 |
| Init roles | 8.1699e-4 | 1.2731e-1 | 4.8910e-3 |
| version header | 4.0883e-4 | 1.2731e-1 | 2.4485e-3 |

SN prior: Beta(89/10000, 19911/10000), a mean break rate of 0.0044 at a
concentration of 2.

**What model 3 reads on the corpus**
(`the_corpus_holds_both_error_rates_and_every_files_tally`):

| | `yes` | `no` | `undecided` |
|---|---|---|---|
| zenoh flows, model 2 | 619 | 0 | 2 |
| zenoh flows, model 3 | 619 | 0 | 2 |
| null flows, model 2 | 0 | 345 | 308 |
| null flows, model 3 | 0 | 0 | 653 |

- The floating-point reading of section 6.7 holds in the reader: no zenoh word
  moves, and every null `no` becomes `undecided`.
- Leaving any group out of the parameters moves no word of its own flows
  (`leaving_a_group_out_of_the_parameters_moves_its_own_flows_by_this_much`).
- Fixtures and the repository's captures that rested on units being added
  moved: a handshake whose capture holds no cookie echo and no SN step weighs
  about eighteen bits and is `undecided`
  (`publisher-priority-encoding-timestamp.pcap`); a flow of keep-alives alone
  never reaches `yes`; generated flows of six other protocols read neither
  `yes` nor `no` at any length.

### 6.9 Model 4: a `no` from what the wire allows (2026-11-02)

Model 4 ships: `model` reads 4, the field document moves to revision 50 and
the session table to revision 8. It takes three decisions, under the owner's
criterion of section 6.7, and corrects the reasoning of D6.

**Why model 3 cannot say `no`, and why D6's remedy was incomplete.** The `no`
sum is `log2` of the other hypothesis's chance of the flow over the likeliest
chance a member of zenoh gives it (D1). Every check of model 3 measures the
zenoh side on 22 groups, and with no group failing, the region lets a new
group fail all of its outcomes with chance up to 0.127 (concentration to
zero). So a flow every outcome of which fails still has a zenoh chance of at
least about 0.127 per check, and its `no` sum stays within a few bits of
zero whatever the numerator is. D6 put the remedy in the numerator: recognise
the flow as a null protocol. A better numerator cannot lower a denominator
that stays above 0.127, so that is not what makes a `no`. What makes one is an
observation whose zenoh chance is DERIVED from what the wire allows, and is
therefore not a rate that a group of zenoh captures could have that the corpus
has not seen. A likelihood per null protocol would still say WHICH protocol a
flow is; it is not part of the zenoh test.

**D9. Model 4 comes before the freeze.** D5 freezes the model once, before a
validation corpus is read, and the validation corpus is read once. Model 4
changes the `no` sum, so freezing model 3 first would spend the validation
corpus on a model about to change. The order is model 4, then the freezing
entry, then the validation corpus.

**D10. The `no` sum rejects zenoh of this wire.** The hypothesis the `no` sum
rejects is that the flow's datagrams were written by an implementation of the
wire this reader reads (protocol version `0x09`: every release of the corpus,
from 1.0.0-alpha.6 to 1.10.2, zenoh-c and zenoh-pico), and reached the capture
each altered with chance at most `epsilon`. A zenoh of another wire (a 0.x
release, a later version that changes the ids) is outside it, so a `no` reads
"not zenoh of this wire". The version header check measures the wire version
where a handshake shows it.

**D11. The first derived observation: the wire's front** (`wire_front`). A
zenoh sender writes a batch at the first byte of a datagram the link delimits
(UDP, raweth). That byte is a transport message's header, whose low five bits
are one of the eight transport message ids `0x00` to `0x07`, or a
`BatchHeader`, whose only value bit is bit 0, so its low five bits are one of
them as well. A front whose low five bits are `0x08` to `0x1F` is therefore an
alteration on the way.

- `epsilon` is `2^-24` when the transport checksum verified: Stone and
  Partridge (2000, "When the CRC and TCP checksum disagree") estimate that
  between one in sixteen million and one in ten billion packets pass the TCP
  checksum with their data altered, and the high end is taken. It is `2^-10`
  when no checksum verified (none carried, raweth, a transmit offload's
  field): the same study found up to one in 1,100 packets failing the TCP
  checksum after the link's CRC had passed. A datagram whose checksum failed is
  not weighed.
- The `no` sum's zenoh side is `epsilon` for a foreign front and one for a
  front of the wire. Its null side is a Beta prior of weight one outcome over
  the flow's own share of foreign fronts, centred on the null members' average
  Jeffreys share.
- The `yes` sum's null side is the members' bound, as for the other measured
  checks, and its zenoh side a prior of weight one outcome centred on
  `epsilon`, so that a flow of fronts of the wire costs the `yes` sum a few
  millionths of a bit.
- A datagram whose front is foreign is not weighed again by `unit_reading`: it
  can read only `undecoded`, and the front already says so. Its reading is
  still counted, and the measured null side of `unit_reading` is now counted
  over the units that are weighed.
- On a stream the length chain from a held start gives one front per
  direction before the framing check judges it, so `stream_framing` covers it.
  Deriving the stream checks is a later step.

The derivation is put to the corpus by
`no_zenoh_file_shows_a_foreign_front`: 27067 fronts of the zenoh files are
weighed and none is foreign. The parameters model 4 adds or moves:

| measured null | `yes` bound per outcome | `no` mean per outcome |
|---|---|---|
| unit readings | 7.9425e-1, 1.0000e0, 8.9950e-1 | 1.5685e-1, 5.9949e-1, 2.4366e-1 |

| check | `yes` bound: of the wire, foreign | `no` prior mean of a foreign front |
|---|---|---|
| wire front | 1.0000e0, 1.0000e0 | 4.5363e-1 |

**What model 4 reads on the corpus**
(`the_corpus_holds_both_error_rates_and_every_files_tally`):

| | `yes` | `no` | `undecided` |
|---|---|---|---|
| zenoh flows, model 3 | 619 | 0 | 2 |
| zenoh flows, model 4 | 619 | 0 | 2 |
| null flows, model 3 | 0 | 0 | 653 |
| null flows, model 4 | 0 | 187 | 466 |

- No zenoh word moves, and leaving any group out of the parameters moves no
  word of its own flows.
- The 187 `no` are DNS 148, mDNS 15, RTPS 10, WS-Discovery 8, SOME/IP 4 and
  SSDP 2. A DNS flow whose id's first byte has its low five bits at most 7
  (about one in four) shows a front of the wire and stays `undecided`; the
  other 148 cross on their first verified datagram.
- NTP, DHCP, CoAP, MQTT and QUIC write an id of the wire at their first byte
  (or are read as QUIC and not as zenoh), and the TCP protocols are streams:
  their 466 flows stay `undecided`, which is what the derived checks so far
  can say about them.
- Generated flows: SSDP and syslog read `no` from three datagrams (no checksum
  vouches for them, about ten bits each), and mDNS, whose id is zero, never
  does. DNS's random id, NTP version 3's first byte and CoAP's eight-byte
  token length are foreign some of the time, so their share of `no` grows with
  the flow; NTP version 4, as the corpus's NTP is, writes an id of the wire.

### 6.10 Model 5: the derivation corrected, and two more derived checks (2026-11-03)

Model 5 ships: `model` reads 5, the field document moves to revision 53 and
the session table to revision 9. It corrects D11 and derives two more
observations, under the owner's criterion of section 6.7.

**D12. D11 left out the lowlatency link.** D11 said a zenoh sender writes a
transport message's header or a batch header at a datagram's first byte. A
unicast link may run lowlatency, and a lowlatency link writes a network
message with no frame around it, on a datagram link at the first byte
(`io/zenoh-transport/src/unicast/lowlatency/link.rs` @
`pub(crate) async fn send_with_link(`, the branch that is not streamed). Its
header's ID is one of the seven network IDs `0x19` to `0x1F`, which model 4
counted foreign: a zenoh flow over UDP with lowlatency would have read `no`
on its first verified datagram. The corpus holds no such flow, so the corpus
test could not see it; a derivation is read off the source, not off the
corpus. A front of the wire is now one of fifteen IDs whatever the flags
(`wz_codecs::wire_const::is_wire_front`): the eight transport IDs and the
seven network IDs. The IDs `0x08` to `0x18` are in neither space.

**D13. A stream's fronts are derived where the capture holds its start.** A
zenoh sender writes each batch of a TCP stream behind a length prefix, so the
first byte past each prefix is a batch's first byte. Where the capture holds a
direction's SYN, the reader's first unit is the sender's first, and each unit
it frames after it, until the chain first breaks, stands where the sender put
one. Each such front is a `wire_front` observation (one check: what the wire
allows at a batch's first byte), of the integrity of the TCP segment that
carried it (`StreamAssembler::integrity_of`).

- The front is judged before the unit's body arrives, so a front that ends the
  chain is weighed as well as one whose unit was read. After the first break
  (a front not credible, a length not possible, a hole the source reported) no
  front is weighed: a scan's resumption point is chosen for looking like one.
- The first front of a direction is the one its framing was first judged at,
  and a foreign front is never one the reader frames behind. When that front is
  weighed and foreign, the lost framing follows from it and `stream_framing` is
  not weighed for that direction; its measured null shares are counted over the
  directions it is weighed for. This is the decomposition D11 made for a
  datagram's unit reading.
- A TLS flow decrypted into its plaintext has offsets of its own and no SYN of
  its own: its fronts are not weighed. Nor, under model 5, were the fronts of
  WebSocket messages, which delimit a batch as a datagram does; model 6
  weighs them (section 6.11).

**D14. The version header's zenoh side is derived.** D10's hypothesis is
zenoh of this wire, every sender of which writes version `0x09` in an Init,
Join, Scout or Hello. Another version in an admissible message read whole is
then an alteration, bounded as a foreign front is, by the integrity of the
bytes that carried it: the datagram's checksums, the weakest of the TCP
segments that carried the unit, or the weaker bound where the reader holds no
verdict (a QUIC payload, a serial frame, a decrypted plaintext). Bytes whose
checksum failed are not weighed. The null side is unchanged (`2^-8` for the
version, the rest for another), so the check takes nothing from the corpus,
and the version header leaves the group-rate checks of section 6.3.

The derivations are put to the corpus by
`no_zenoh_file_refutes_a_derived_check`: 49326 fronts of the zenoh files are
weighed, 22259 of them on stream chains and 27067 on datagrams, and none is
foreign; 1222 version headers are weighed and none is another version. The
parameters model 5 moves:

| measured null | `yes` bound per outcome | `no` mean per outcome |
|---|---|---|
| unit readings | 7.7639e-1, 1.0000e0, 9.0270e-1 | 1.1127e-1, 4.9302e-1, 3.9571e-1 |
| stream framing | 6.0503e-2, 1.0000e0 | 8.0432e-3, 9.9196e-1 |

| check | `yes` bound: of the wire, foreign | `no` prior mean of a foreign front |
|---|---|---|
| wire front | 1.0000e0, 1.0000e0 | 4.6807e-1 |

**What model 5 reads on the corpus**
(`the_corpus_holds_both_error_rates_and_every_files_tally`):

| | `yes` | `no` | `undecided` |
|---|---|---|---|
| zenoh flows, model 4 | 619 | 0 | 2 |
| zenoh flows, model 5 | 619 | 0 | 2 |
| null flows, model 4 | 0 | 187 | 466 |
| null flows, model 5 | 0 | 234 | 419 |

- No zenoh word moves.
- The 234 `no` are DNS 102, Redis 60, HTTP POST 28, SSH 17, RTPS 10, SMTP 10,
  WS-Discovery 4, SSDP 2 and SOME/IP 1. The streams cross on their first
  front: the reader takes their first two bytes for a length prefix, and the
  byte past it (a letter, a digit or a line end) is no batch's first byte.
  PostgreSQL's and MQTT's are IDs of the wire, and those flows stay
  `undecided`.
- Fewer datagram flows cross than under model 4, by D12: a DNS id, an mDNS
  id, a SOME/IP service id or WS-Discovery's `<` whose low five bits are
  `0x19` to `0x1F` is now a front of the wire.
- Generated flows: SSDP reads `no` from three datagrams; syslog's `<` and
  mDNS's zero id are fronts of the wire, and neither reads `no` at any length.
  DNS reads `no` in 169, 285, 487, 581 and 600 of 600 flows of 3, 5, 10, 20
  and 50 datagrams, and CoAP in 78, 176, 307, 434 and 574.

### 6.11 Model 6: a WebSocket message's front (2026-11-03)

Model 6 ships: `model` reads 6, the field document moves to revision 54 and
the session table to revision 10. It derives the observation section 6.10
left for later.

**D15. A WebSocket message's front is derived where the upgrade is the
stream's start.** zenoh's WebSocket link is not streamed: each write is one
Binary message holding one batch, so a message delimits a batch as a datagram
does, and its first payload byte, unmasked, is a batch's first byte. It is a
`wire_front` observation where two things hold, for the reason D13 gives for a
stream: the capture holds the direction's SYN, so the HTTP upgrade the deframer
stepped over was the stream's first bytes; and the deframer has not lost its
framing since, so no message was found by a scan, which accepts a frame for
looking like a zenoh batch. A flow classified as WebSocket after its opening
was lost starts in a scan, and none of its fronts is weighed. The integrity is
the weakest of the segments that carried the byte and, on a masked frame, the
key it is read through. A message whose front is foreign is not weighed again
by `unit_reading`, as a datagram's is not.

**The scan's own test, by D12.** The deframer's scan (a resynchronisation, or
the classification of a flow whose opening was lost) accepted a frame only if
its first payload byte was a credible transport header, 42 of 256 bytes. That
refused every frame of a lowlatency link, so a lowlatency zenoh session over
WebSocket that lost a segment lost every message after it. The scan now asks
`is_credible_lowlatency_header` (98 of 256): a transport header whose flags
its message defines, or a network header. A batch header of `0x00` (an
uncompressed batch on a link that negotiated compression) is still refused:
zero runs are common in any payload, and accepting it let a zero-filled buffer
confirm a chain, which two tests of the reader caught. A compressed link's
uncompressed batch is therefore not a point a scan resumes at; the next
compressed or plain one is. `the_ws_chain_discriminator_refuses_noise` measures
the wider test: depth 4 is still the shallowest that accepts no noise buffer
and no real zenoh stream (noise accepted 40, 35, 4 and 0 of 40 at depths 1 to
4), so `WS_CHAIN_DEPTH` stays 4.

No word of the corpus moves and no front of it is added: the corpus holds no
WebSocket capture. The validation corpus is where D15 meets the wire.

### 6.12 The freeze: model 6, registered before the validation corpus (2026-11-03)

This is the entry D5 asks for. It registers the model the validation corpus
will be read against, and how that corpus is read, before any of its files
exists. It moves nothing in the reader.

**What is frozen.** Model 6 as the reader at this entry computes it:

- The rule: each sum is the `log2` of an e-process against the hypothesis it
  rejects (D1); that hypothesis's unknown rates are taken at their likeliest
  over the 95% region its corpus allows, the other side mixed over a prior
  fixed in advance; every term rounded toward the rejected side (D3, D8). The
  word is the first crossing of `+20` bits (`yes`) or `-20` bits (`no`), and
  it latches (D4).
- The rejected zenoh hypothesis is zenoh of this wire, version `0x09` (D10),
  whose bytes reach the capture altered with chance at most `2^-24` where the
  transport checksum verified and `2^-10` where none did (D11).
- The checks and where they are weighed: the cookie echo, the Init roles, the
  version header (D14), the SN steps, the unit readings, the stream framing,
  and the fronts of datagrams, of stream chains held from their SYN (D13) and
  of WebSocket messages read from the upgrade on (D15), each front against the
  fifteen IDs of D12.
- The measured parameters: `zenoh_calibration_generated.rs` as the development
  corpus gives it (22 zenoh groups, 18 null files), the zenoh priors of weight
  one outcome at the Jeffreys estimate, the SN prior Beta(89/10000,
  19911/10000), the null side's bounds and means, the front's null prior.
- The groups of section 6.3: a null protocol, a zenoh release line, a link
  condition, a workload.

`the_model_is_the_one_frozen_before_the_validation_corpus` holds all of it as
one digest, `0xace0388900a8cc99`, the same in every build of the reader. A
change to any of it fails that test until a ledger entry registers the new
digest, so a model that has changed cannot be read against the validation
corpus under this entry's name.

**What the validation corpus is.** Captures of what the development corpus
lacks (section 6.4): queries and replies, liveliness, fragmented payloads,
priorities other than the default, authentication, multicast, an
implementation other than the reference one, a lowlatency link (D12) and a
WebSocket link (D15); and null protocols the development corpus does not hold.
Each file names its group. The files sit apart from `captures/corpus/` and are
counted into no weight until the report below is written.

**How it is read, once.** The report states, by group:

1. The errors: every zenoh group with a flow that reads `no`, and every null
   group with a flow that reads `yes`. Any one refutes the frozen model and is
   reported as a refutation.
2. The model's validity (section 6.4, second layer): the share of groups whose
   sums cross `+1` to `+10` bits and `-1` to `-10` bits, each with its exact
   95% interval, against the level.
3. The operating characteristics: the units a flow needs before its word, per
   group, with the 95th percentile.

The report is judged at the interim level of section 6.4: a group fails with
chance at most 10%, which needs 29 groups a side. After the report the
validation files may join the development corpus and the model may change, and
the next freeze needs a validation corpus of its own.

