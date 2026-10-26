# Session lifecycle: one intent contract, verified identity, three transports

Status: design note. It states what is built, what is measured, what is decided
and what is still open; it is not a specification and the atomic store does not
parse it. Decisions here follow the standing criterion of this tree (the
long-term correct design, cost not counted); the reason for each is next to it.
It continues open-debt item 761 and amends the meaning, not the grammar, of the
verbs that item fixed on 2026-09-17.

## 1. The question

A command on the rail can close a running session, and on the AP profile it can
ask for a session to be opened (atom `session-close-ingress`). On the
fixed-memory MCU profile an open is refused, because no opener is bound there.
The question is what the shape is so that opening, closing and resetting a
session is correct on every profile, on every channel the command can arrive
by, and on a profile whose peers are fixed when the image is built, while the
node stays interoperable with zenoh 1.10.1 and zenoh-pico 1.10.1 peers.

## 2. What is built, and what is measured (2026-10-23)

- **The ingress, the authority and the opener port exist once, in
  `wz-session-core`.** `drive::SessionLifecycleInjector` takes a
  `SessionLifecycleAuthority` and an `Option<&dyn SessionOpener>`
  (`crates/wz-session-core/src/drive.rs` @ `pub trait SessionOpener {`). A host
  with no opener refuses an open and logs that it did.
- **The AP opener drops the identity it resolved.** `LinkstateOpener` finds the
  key's zid in the link-state directory and sends
  `ConnectReconcile::Add(Vec<AnyLocator>)`
  (`crates/wz-runtime-tokio/src/session_lifecycle_open.rs` @
  `impl SessionOpener for LinkstateOpener {`). The desired connect set is keyed
  by locator, so the dial it causes carries no expected zid: nothing on that
  path can tell the node it was meant to reach from another node now answering
  at the same locator.
- **The C ABI checks the peer, but after the session is open.**
  `open_scouted` compares the peer's zid once the handshake has completed and
  then drains the session (`crates/wz-capi-core/src/drive.rs` @
  `async fn open_scouted(`).
- **The fixed-memory profile has the host an opener needs.**
  `wz_session_mcu::slot_host::SessionHost` opens sessions in `S` static slots
  (`pub fn dial<F>(`), and the lwIP host delegates to it. One slot is
  36,776 B on `thumbv7m-none-eabi` (`deploy/session_slot_bytes.json`).
  `wz-session-lwip` does not forward `session-close-ingress`.
- **Upstream already holds most of this, internally.** In zenoh 1.10.1:
  - `Runtime::connect_peer` is idempotent: a peer already connected is
    reported as success and not dialled again
    (`zenoh/src/net/runtime/orchestrator.rs` @ `pub async fn connect_peer(`).
  - The dial carries the expected zid. The establishment compares it with the
    InitAck's zid and closes with `close::reason::INVALID` before OpenSyn
    (`io/zenoh-transport/src/unicast/establishment/open.rs` @
    `pub(crate) async fn open_link(`).
  - The admin write plane inserts configuration values and nothing else, and
    has no session verb (`zenoh/src/net/runtime/adminspace.rs` @
    `fn send_push_consume(`).
  - The public-key authentication proves the INITIATOR's key only. The
    responder reads back a challenge sealed under the initiator's key, while
    the initiator's last stage checks the OpenAck for presence alone
    (`io/zenoh-transport/src/unicast/establishment/ext/auth/pubkey.rs` @
    `async fn recv_open_ack(`), so a responder presenting another node's
    public key completes the handshake. The initiator's lookup admits the
    responder's key; nothing proves it.
  - The public-key authentication names no zid. Its allow list is a set of
    keys, so a holder of a known key can claim any zid
    (`io/zenoh-transport/src/unicast/establishment/ext/auth/pubkey.rs` @
    `lookup: Option<HashSet<ZPublicKey>>,`).
  - zenoh-pico 1.10.1 has no authentication extension; TLS with mutual
    authentication is its only credential. Its TLS stream is Mbed TLS written
    against POSIX socket headers (`src/link/transport/upper/tls_stream.c` in
    the zenoh-pico tree).
  - The TLS configuration takes certificates, not raw public keys: a root,
    a certificate and key per side, a switch for mutual authentication and
    one for name verification (`commons/zenoh-config/src/lib.rs` @
    `enable_mtls: Option<bool>,`).
- **A public-key proof is not bound to the channel it was made on.**
  `peer_identity_verified` accepts the zid the acceptor's public-key stage
  proved (`crates/wz-session-core/src/session_actions.rs` @
  `pub fn peer_identity_verified(`), and on a TCP link the frames after the
  handshake carry no integrity protection. A party on the path can let the
  handshake complete and then insert a Push carrying a verb, and the session
  it arrives on still reports a verified peer.

## 3. Decisions

**D1. A zid that takes part in lifecycle verbs is derived from the public key
of the credential it authenticates with.** The zid is the first 16 bytes of
SHA-256 over the DER `SubjectPublicKeyInfo` of that key, and the key is the
one the peer's certificate carries on a secure channel (D9), so the rule
covers peers whose only credential is TLS, zenoh-pico among them. A node can
then claim a zid only by holding the private key, and no certificate authority
is needed. This is the
self-certifying identifier of HIP (RFC 7401, the Host Identity Tag) and of SFS
(Mazières et al., 1999). A peer whose zid is not derived this way still
exchanges data as before; it cannot command a lifecycle verb or be the
verified target of one. A key counts as a credential only when it is proven
inside a channel whose every frame is integrity-protected under keys the
same handshake derived (D9). An authenticated handshake followed by
unprotected frames proves who started the session, not who sent a later
message (Canetti and Krawczyk, 2001; channel binding, RFC 5056). The
public-key extension is therefore an admission check, not a credential for
the verbs. Rejected: the upstream rule, a known key with any zid,
because the ACL decides on the zid and the zid would then be unauthenticated.
Rejected: binding the zid to a name in the certificate, because that needs a
public-key infrastructure the self-certifying form does not.

**D2. Lifecycle verbs are accepted only from an authenticated peer, and a
profile with no secure channel does not compile them.** The authority judges
the zid verified under D1, so a verb is taken only from a link of D9's kind,
and the build-time guard is keyed on the secure-channel features (TLS and QUIC
on AP, D9's channel on the fixed-memory profile), not on the authentication
extension. Authorization is meaningful only over authentication
(Lampson, Abadi, Burrows and Wobber, 1992). A build without a secure
channel fails closed rather than exposing a destructive verb that cannot be
recalled, which is the reason item 761 put the ACL first.

**D3. Identity and location are separate.** A `LocatorDirectory` maps a zid to
candidate locators, each with its source and the time it was last confirmed.
The sources are the build-time declaration, scouting `Hello` messages and the
link-state flood (AP). Entries are soft state: they expire unless refreshed
(Clark, 1988; Raman and McCanne, 1999). A locator is a hint for reaching an
identity, never the identity itself (LISP, RFC 9300 and RFC 9301; ILNP,
RFC 6740). The AP opener's link-state lookup becomes one source.

**D4. Every dial made for an identity carries the expected zid, and the check
is at InitAck.** On a mismatch the link closes with the INVALID reason before
OpenSyn, at the same point as upstream. This applies to the AP reconcile path,
the C ABI's scouted open (whose later check moves to this point) and the MCU
opener. Without it, D3's hints could connect to a node that was not asked for.

**D5. Each peer has a connection state machine, and the verbs are its
administrative events.** The model is the BGP peer state machine (RFC 4271,
section 8): a configured neighbour, `ManualStart` and `ManualStop`, a connect
retry timer, and damping of an oscillating peer. `open` is `ManualStart` and
`close` is `ManualStop`. The states are Idle, Resolving, Connecting,
Established, Backoff and Refused; Refused names its cause (no slot, no
locator, identity mismatch, authority refused). The machine is SCXML generated
by SCE, like the session machine. The retry waits are upstream's
`connect.retry` schedule, already transcribed once
(`crates/wz-session-core/src/retry_period.rs` @ `pub struct RetryPeriod {`).
The peer table is bounded by a compile-time capacity on the fixed-memory
profile, and a session slot is a resource the machine acquires and releases.

**D6. Intent and status are separate, and every verb is idempotent.** The node
holds the set of peers it should be connected to (intent) apart from the
sessions it has (status), and the machines of D5 converge status to intent.
The grammar of item 761 stays, `@/<zid>/<whatami>/session/<verb>/<peer-zid>`:

| verb | effect on intent | effect on sessions |
|---|---|---|
| `open` | adds the peer | the machine connects; a second `open` changes nothing |
| `close` | removes the peer | the session closes and is not re-dialled |
| `reset/<generation>` | none | closes once per generation; a peer still in intent reconnects |

The reason is the channel. The port answers nothing (R2670), so a sender
learns the outcome only by observing it and can only retransmit; a
retransmission is safe only if the operation is idempotent (Saltzer, Reed and
Clark, 1984). `reset` is the one operation that is not idempotent by nature,
so it carries a generation, the duplicate suppression of at-most-once calls
(Birrell and Nelson, 1984). Each peer's machine state is readable by a GET on
`@/<zid>/<whatami>/session/status/<peer-zid>`, so the outcome of a reply-less
verb is observable. The intent's baseline is the build-time declaration;
runtime edits are volatile and do not survive a restart.

This amends the meaning of decision 2 of item 761. That decision put the verbs
under `session/` rather than `config/` so that they would not carry the meaning
"writing the same value again is harmless". The verbs stay under `session/`:
intent is run-time state of the session layer, not node configuration. What
changes is that each verb is idempotent, because on a channel without a reply
nothing else is safe to retransmit.

**D7. One contract, three transports.** The semantics of D5 and D6 are one
contract that does not depend on how a command arrives. A target is either a
zid, resolved through D3 and verified through D4, or a locator with an optional
expected zid. A target without an expected zid is accepted only when the
authority admits locator targets.

1. **In-band:** a Push on the keyexpr of D6.
2. **Out-of-band:** a test agent hosting the node drives it through the
   agent's own control channel and maps each command onto the contract. The
   agent's protocol must keep the contract's idempotency: a repeated open of
   an open session is success, not an error, or a retransmission reads as a
   failure. The agent writes the session's intent and nothing else: the
   application calls (declare, put, get) it makes through the node's own
   client interface, so the control boundary is one and not two. What 7d
   built of this is the `open` command alone, on the fixed-memory profile
   (see Open, the out-of-band remainder).
3. **Build-time declaration only:** the verbs are off, the intent is the
   declared peer set, and the machines only reconnect.

The transport is a value of a build configuration axis, so a fixed profile
whose peers are known when it is built is the third value of the same design,
not a separate one.

**D8. On zenoh this is a wz extension.** The wire is unchanged (a Push, the
standard Init and Open exchange, a 16-byte zid), so zenoh and zenoh-pico nodes
interoperate as peers and as targets. A zenohd that should accept the verbs
needs either an upstream change or a plugin calling `Runtime::connect_peer` and
closing the transport. Proposing either upstream is the owner's decision.

**D9. The credential is a secure channel, and every profile uses one
protocol for it: TLS 1.3 with mutual authentication (RFC 8446).** Each side
signs the handshake transcript with its key, so each proves possession to the
other, including the side that dialled; this is the SIGMA design (Krawczyk,
2003), and TLS 1.3's handshake has been verified formally (Cremers et al.,
2016 and 2017). The record layer then protects every frame under keys that
handshake derived, which is the binding D1 requires.

- **The key and the identity.** A certificate is only the container of the
  key. It is self-signed, and a peer is trusted by pinning the zid D1 derives
  from its key, never through a certificate authority. The semantic ideal is
  a raw public key (RFC 7250); the container is X.509 because upstream's TLS
  configuration takes certificates. The same construction is the libp2p TLS
  handshake, where a peer's identifier is the hash of the key in a
  self-signed certificate. The baseline algorithms are ECDSA over P-256 and
  ECDHE, which every stack this tree meets supports; the algorithm is named
  inside the SubjectPublicKeyInfo, so a later algorithm changes no identity
  rule.
- **One port, one implementation per profile.** The session tier owns a
  secure-channel port whose handshake yields the peer's
  SubjectPublicKeyInfo and a protected stream. AP implements it with the
  existing TLS and QUIC links. The fixed-memory profile implements it with a
  TLS 1.3 stack that plays both roles, authenticates both sides and runs in
  static memory, placed under the session as an upper transport over its
  link, where zenoh-pico places its own TLS stream. The stack is chosen on
  those properties, on constant-time arithmetic, on active maintenance and on
  a permissive licence compatible with this tree's licence; Mbed TLS 3.6 LTS
  is the candidate, and its fit is measured first. Writing a TLS stack here is
  rejected (cryptography is not re-implemented), and the port lets a mature
  Rust stack with no heap replace the choice later.
- **The fixed-memory stack, decided (owner, 2026-10-24).** Mbed TLS on its
  PSA Crypto line (4.x), at the one revision the Zephyr workspace pins, and
  the same revision as a pinned source for the profiles that are not Zephyr.
  The PSA line does every cryptographic operation through the PSA Crypto API,
  which is what lets the chip's crypto block serve as a driver and lets a
  private key be opaque to the application. The 3.6 line is the last of the
  older API, and on the kit it would be a second copy beside Zephyr's.
  zenoh-pico 1.10.1 refuses Mbed TLS 4 in its own build
  (`vendor/zenoh-pico/CMakeLists.txt`); that constrains building pico, not
  the TLS 1.3 wire both sides speak. The structure:
  - The identity key is a P-256 key the device generates in the PSA key store
    at its first boot. The key never leaves it, and the handshake's
    CertificateVerify is signed inside it. The certificate is self-signed on
    the device over that key, and the zid is derived from the key (D1).
  - A peer is accepted by pinning, not by a chain. Its certificate's key
    proves possession in the handshake, and the zid D1 derives from it must
    equal the zid the dial expected (D4). There is no certificate authority,
    so a chain error is not the verdict.
  - Memory is one static arena that Mbed TLS's buffer allocator serves. The
    tree has no heap. The record buffers are bounded by the record size limit
    (RFC 8449, which this line implements on both sides) and by the
    configured record lengths. A peer that ignores the limit still sends
    16 KiB records, so whether the receive buffer can shrink is measured
    against the peers, not assumed.
  - The session tier sees one port. The channel is a stream over a stream
    (`TlsStream<S: StreamSocket>: StreamSocket`), so the stream link's
    framing, loss handling and lent-slot send stay written once. The locator
    gains a TLS link kind, and a stack without it refuses the dial as
    unsupported. The backend is its own crate behind the port.
  - First, the fit is measured on the kit: an image runs a mutual TLS 1.3
    handshake between two in-memory peers. It reports code size, the arena's
    peak, and each role's handshake time, as a row of the kit lane.
  - **Measured (Round 3493, T2G kit, M7 at 350 MHz, image
    `deploy/zephyr-tls-fit`, Zephyr's Mbed TLS 4.1.0).** The lane image is
    `zephyr-tls-fit`.
    - Three rounds of mutual TLS 1.3 completed with
      TLS_AES_128_GCM_SHA256. Each side pinned the other's zid, and a wrong
      expected zid was refused.
    - Each role's handshake took about 1.76 s, in software P-256 with the
      NIST curve optimisation on.
    - Generating the two identities (key and self-signed certificate)
      took 1.56 s together.
    - The arena's peak was 14,368 B in 95 blocks for both peers together,
      with Zephyr's default record lengths of 1,500 B each way.
    - The main thread used 2,336 B of stack.
    - The link map puts Mbed TLS at about 72.7 KB of code and read-only
      data: crypto 42.4 KB, TLS 18.2 KB, X.509 12.2 KB.
  - **The record buffers, decided and measured (Round 3495).**
    - The receive buffer is the protocol's maximum of 2^14 bytes. rustls
      0.23, which zenohd 1.10.1 links, does not implement the record size
      limit (its source has no such extension). zenoh's TLS link sets its
      MTU to the largest batch and leaves rustls's fragment size at its
      16 kB default (`io/zenoh-links/zenoh-link-tls/src/lib.rs` @
      `const TLS_MAX_MTU: BatchSize = BatchSize::MAX;`).
    - Data records from a zenoh peer do stay within the negotiated batch,
      because both establishment sides take the smaller batch
      (`io/zenoh-transport/src/unicast/establishment/accept.rs` @
      `.min(init_syn.batch_size)`;
      `io/zenoh-transport/src/unicast/establishment/open.rs` @
      `state.transport.batch_size = state.transport.batch_size.min(init_ack.batch_size);`),
      and rustls writes a record per write. That is an implementation's
      behaviour, though, not a bound the protocol gives.
    - rustls also joins a whole handshake flight into one record
      (`HandshakeFlight`), so how large that record is depends on the
      certificate the peer presents.
    - The send buffer is ours to bound. The largest record this end wrote
      was 341 B, a certificate message over a 293 B self-signed P-256
      certificate. A data record is a batch of at most 1,024 B with its
      2-byte length, so 1,500 B holds both.
    - Measured on the kit with 16,384 B receive and 1,500 B send: the
      arena's peak is 44,136 B for both peers together, about 22 KB per
      session, against 14,368 B with 1,500 B both ways.
    - The handshake took about 1.45 s per role, and the identities 1.28 s.
      That is 18 % below the first run's figures, and the record lengths
      do not change the arithmetic, so the difference is not explained.
    - Negotiating the record size limit with peers that implement it, and
      then shrinking the receive buffer, is a later saving. It is not a
      bound the channel can rely on today.
  - **The channel behind the stream port, landed (Round 3502).**
    - The port. The cooperative runtime's stream seam is split in two:
      `StreamSocket` is the I/O of a connected stream and `StreamDial` the
      value a stack holds to open one
      (`crates/wz-runtime-coop/src/stream_link.rs`). The dial carries what
      opening needs besides an address, here the identity, so the channel
      is a stream like a plain connection and the stream link is unchanged.
    - The backend. `crates/wz-tls-mbedtls` builds the pinned source
      (`vendor/mbedtls`, `vendor/tf-psa-crypto`, the revisions `west.yml`
      pins) through its own CMake with a configuration that states the kit
      image's choices (`crates/wz-tls-mbedtls/config/`). Its C side keeps
      every Mbed TLS structure in the arena, and Rust holds only pointers,
      so no layout crosses the boundary. `TlsStream<S>` is a
      `StreamSocket` over `S`, and `TlsDial<D>` connects `D` and completes
      the handshake before the link sees a byte.
    - Measured on the host. Two sessions of the crate complete mutual
      TLS 1.3 and each derives the other's zid, which equals the session
      core's derivation over the same key
      (`wz_session_core::credential_identity::zid_from_spki_der`). The
      arena peak for both is 49,008 B on a 64-bit host.
    - Measured against the peer zenohd is. The test builds a rustls 0.23
      server the way zenohd 1.10.1 builds its TLS server with mutual TLS on
      (`io/zenoh-links/zenoh-link-tls/src/utils.rs` @
      `let client_auth = WebPkiClientVerifier::builder(root_cert_store.into()).build()?;`).
      Its root store holds only the device's own self-signed certificate.
      The dial completes, the device names the router by the key the router
      proved, and a batch crosses both ways. A router that pins another
      certificate refuses the device. This answers, at the rustls level,
      the open question of whether upstream admits a pinned self-signed
      certificate. A zenohd process over the link is the next measurement.
    - The locator kind, landed (Round 3505). `tls/a.b.c.d:port` names
      `LinkProto::Tls`. A stack carries a secure channel only when it is
      given one (`IpStack::with_tls`, `IpLinks::with_tls`); without one, a
      `tls/` dial is unsupported before any buffer is claimed, so it is
      never mistaken for a full table to retry. A stream names its own
      protocol (`StreamSocket::PROTO`), so the link's two ends read `tls/`
      over a channel. On the host, the posix links given the Mbed TLS
      channel open a `tls/` link to the rustls router above, and the
      router verifies the device.
    - The proven key reaches the session on every profile (Round 3510). A
      link driver answers `peer_credential_zid`, a value rather than the
      heap profile's `LinkSubject` reference, and
      `peer_identity_verified` reads only it. A stream link asks its
      stream, and `TlsStream` answers with the key its peer proved. The two
      reconnect seams hand on their live link's answer, so a reconnecting
      session over TLS is verified by the link it runs on now. Before this
      the seams answered nothing and such a session was never verified.
    - The verbs are back on the cooperative profile, through the channel
      (Round 3513). The runtime offers no lifecycle feature, because it
      cannot promise a channel. `wz-tls-mbedtls` offers
      `session-close-ingress` and always states `secure-channel`, so every
      cooperative build with the verbs has the channel too. The guard gate
      builds the runtime with the verbs and no channel, which is refused,
      and the channel crate with the verbs, which builds.
    - The witness step 1b names, on the host (Round 3520). The image is
      `deploy/host-slot-node` built with `tls`: the kit's session code as a
      Linux process with no allocator, which generates its identity at start
      and prints its certificate as PEM. The router is zenohd 1.10.1 with
      mutual TLS on, pinning that certificate as its `root_ca_certificate`.
      Three runs, each the control of another
      (`crates/wz-integration-tests/tests/wz_fixed_memory_tls_zenohd_interop.rs`,
      Layer Z):
      - A router whose zid its key names is admitted, and the image reads it
        as verified.
      - A router claiming another zid is admitted over the same channel and
        read as not verified, so the first verdict is the key binding, not
        the channel alone.
      - A router pinning another device admits no session, so the router did
        verify the image.

      The node's zid is the one its key names. Before `wz_tls_start` hands
      Mbed TLS the arena, its allocator is one that refuses, so the image
      references no C heap symbol and still names no Rust allocator (the
      no-allocator gate's `linux-x86_64-tls` build).
    - The same witness on the kit (Round 3524). The T2G kit's fixed-memory
      client, built with `CONFIG_WZ_TLS`
      (`deploy/zephyr-admin-node/overlays/t2g_client_tls.conf`), dials
      `tls/` over Zephyr's TCP (`wz_runtime_zephyr::stream`). Its channel's
      C side is compiled by the image's CMake against Zephyr's own Mbed TLS
      4.1.0, and its arena is the one Zephyr gives Mbed TLS. The kit lane's
      verify image (`scripts/kit-lane.sh`, `zephyr-client-fixed-tls`) does
      the rest:
      - It resets the kit with no router and reads the certificate the
        image prints.
      - It configures zenohd 1.10.1, built at the pin, to pin that
        certificate and to claim the zid its own key names.
      - It holds the run to the image's line, which on the first run read
        "session established, peer verified".
      - Against the same client without the channel, the image grew by
        109,604 B of code and 68,781 B of bss, of which 49,152 B is the
        Mbed TLS arena.
      - Past the verified line the lane asks the image's two documents
        through the router 2,000 times each, as for an answering image,
        and holds the run to the image's row in `deploy/resource_budget.json`
        (Round 3530). The row is set from 8 runs, alternated with the client
        without the channel:
        - The main thread's stack peak is 6,864 of 12,288 B in 8 of 8 runs,
          under the stack gate's static chain of 7,016 B.
        - The GET median is 644 us (the runs' medians span 0.583 to
          0.765 ms). The client without the channel gave 0.395 to 0.472 ms
          in the same sitting, so the channel costs about 0.25 ms on a GET
          at the median.
  - What this leaves open:
    - Mbed TLS 4.1 does not implement TLS 1.3 KeyUpdate. A KeyUpdate from
      the peer ends the session with an unexpected-message alert: the
      post-handshake dispatch takes a NewSessionTicket and refuses every
      other message (`vendor/mbedtls/library/ssl_msg.c` @
      `/* Fail in all other cases. */`). rustls updates its keys before
      AES-GCM's record limit,
      so a link that carries that many records from one peer is cut. The
      way out is upstream support or a link that reopens. Not measured.
    - The handshake time is software P-256 throughout. The p256-m driver
      and the chip's crypto block, which is reached as a PSA driver, are
      the two ways to shorten it.
    - The keys here are volatile. The persistent PSA key store is the
      production form.
    - The pin is checked after the handshake and before any data. The
      trusted-certificate callback would check it inside the handshake.
- **Rejected.** EDHOC (RFC 9528), the constrained-device design, because no
  zenoh or zenoh-pico peer speaks it and it needs OSCORE to protect messages,
  which would make a wz-only channel. Noise (XX or IK), for the same
  interoperation reason. Porting the public-key extension to fixed memory,
  because it is not bound to the channel (section 2), it proves only the
  initiator, and both of its roles need an RSA private-key operation.

## 4. Steps

Each step lands with its own done-when; sizes are not estimated here.

1. **D1 and D2.** In two parts.
   - **1a, landed (Round 3455), corrected (Round 3463).** The derivation
     (`wz_session_core::credential_identity`), the proof on the TLS and QUIC
     path (a link records the zid of its peer certificate's key),
     `peer_identity_verified` on the session, and the lifecycle injector
     refusing an unverified commander before its authority is asked. Round 3455
     also took the public-key stage's proof as a credential and carried it
     through the accept cookie; D9 rules that out, and Round 3463 removed it
     with the cookie member and the session field that held it. An earlier
     draft of this step also listed the initiator's check of the responder key;
     that check was built by R311y576, and it admits a key without proving it,
     which is why it is not a credential here.
   - **1a correction, landed (Round 3463).** A peer proven only by the
     public-key extension over plain TCP is refused; the same zid over mutual
     TLS is admitted, on both sides; over one-way TLS the client verifies the
     server and the server verifies nobody. Witnessed end to end over loopback
     in each case, and through the injector.
   - **1b.** The verbs do not compile in a build with no secure channel (D2),
     and the fixed-memory profile gets D9's channel. Done when a build with
     the lifecycle feature and no secure-channel feature fails to compile, and
     a fixed-memory image and a router each verify the other over it.
   - **1b, the D2 guard, landed (Round 3491).** `wz-session-core` has a
     `secure-channel` feature that adds no code. The AP's TLS and QUIC link
     features turn it on, and a `compile_error!` refuses `session-close-ingress`
     without it. The verbs are no longer forwarded to the cooperative runtime,
     which has no channel. Every lane that builds the verbs now names a channel.
     `lifecycle-channel-guard-gate.sh` builds the refused combinations, and it
     fails when the guard is removed. Left of 1b: D9's channel on the
     fixed-memory profile, which brings the verbs back to it.
   - **1b, the channel on the fixed-memory profile (Rounds 3502 to 3513).**
     `wz-tls-mbedtls` behind the stream port, the `tls/` locator kind, the
     proven key read by the session on every profile, and the verbs offered
     by the channel crate (D9 above). Done on the host (Round 3520): the
     fixed-memory image `host-slot-node` and zenohd 1.10.1 verify each other
     over the channel, with two controls. Done on the kit (Round 3524): the
     T2G kit's fixed-memory client and zenohd 1.10.1 verify each other over
     the channel. Step 1b is done. The kit image's stack and resource rows
     are set from its runs (Round 3530).
2. **D4.** The expected zid on every dial path. Done when a dial to a locator
   that answers with another zid closes at InitAck on AP, the C ABI and the MCU
   host.
   - **2a, the check in the session, on every profile (Round 3537).** An
     opener names the node with `SessionLinkActions::expect_peer_zid` before
     the handshake. The dispatcher compares it with the InitAck's zid in
     `SentInitSyn`, after the InitAck's extension checks and before the
     OpenSyn's bound is decided, as upstream does. On a mismatch it drives
     `framing.error`, so the session closes INVALID with no OpenSyn, and
     returns `DriverLoopOutcome::InitAckPeerMismatch`. The tokio open loop
     maps that to `OpenError::InitAckPeerMismatch`. Both spellings of one zid
     (the wire's trimmed bytes and the sixteen-byte form) are the same zid
     (`credential_identity::zid_from_wire`). A dial that names no node is
     unchanged. The slot grew by 24 B (36,776 B on `thumbv7m-none-eabi`).
     Witness: `crates/wz-runtime-tokio/tests/session_fsm_driver_loop.rs`, one
     InitAck refused for a dial made for another node and admitted for a dial
     made for it.
   - **2b, the AP opener (Round 3539).** `LinkstateOpener` sends
     `ConnectReconcile::AddNode`, the node's zid with the locators it
     advertised, and each becomes a dial plan for that zid
     (`MeshDialTarget::expected_zid`). The face template's staging installs
     it on the session of every dial and re-dial of that plan, the way
     upstream's `connect` dials each scouted locator for its zid. A plain
     `Add` and the startup seed still name no node. Witness:
     `crates/wz-runtime-tokio/tests/connect_and_open_session.rs`, where one
     far end answers every InitSyn with the same InitAck. A dial made for
     another zid sends a Close carrying INVALID and no OpenSyn. A dial made
     for the zid it carries sends its OpenSyn.
   - **2c, the C ABI's scouted open (Round 3542).** `open_scouted` dials the
     locator a Hello gave for the node that sent it. Its check after the
     handshake (compare, then drain the session) is gone. The node's zid is
     installed by the dial's staging, so a link another node answers closes
     at its InitAck with no OpenSyn, and the open is `LinkFailed`, as before.
     Witness: `crates/wz-capi-core/src/drive.rs`, the two
     `a_scouted_open_*` tests over one far end. The cooperative engine of the
     C ABI has no scouting, so it has no scouted open to change.
   - **2d, the fixed-memory host (Round 3542).** `SessionHost::dial`
     (`wz_session_mcu::slot_host`) takes the node a dial is made for, and
     lwIP's host takes it as a `DialTarget` (an address, or an address and a
     zid). It is installed after the open and before the session's task first
     runs, which is before the InitSyn leaves. A configured endpoint names no
     node. Witness: `crates/wz-session-lwip/tests/session_dial_for_a_node.rs`
     on the lwIP loopback, on the node's real profile. The MCU opener of step
     6 dials through it.
   - The rule that two spellings of one zid are one zid is written once,
     `credential_identity::canonical_zid`, in the module every profile builds.
     `zid_hex` re-exports it.
   - D4 is done: on AP, on the C ABI and on the fixed-memory host, a dial
     made for a node closes at an InitAck from another zid, before any
     OpenSyn and with INVALID.
3. **D3.** The directory and its three sources, with expiry.
   - **3a, the directory (Round 3544).** `wz_session_core::locator_directory`
     holds a zid's candidate locators in a fixed number of rows, with no
     allocator, so every profile holds the same table. A row is one hint (a
     zid and a locator). Each of the three sources (`Declared`, `Hello`,
     `Linkstate`) confirms it with its own end, and a lookup never returns a
     hint whose every confirmation has ended. The directory is the mechanism
     only: each confirmation carries its `Lifetime`, because only the source
     knows how often it refreshes. A declared hint is `Permanent` and leaves
     only when it is withdrawn; a soft-state one must have a lifetime. A
     withdrawal takes one source's confirmations of a zid away and keeps the
     others. Candidates come declared first, as the operator's intent, then
     the most recently confirmed first. A full table displaces the soft-state
     hint whose last confirmation ends first, never a declared one, and a
     table of declared hints refuses and counts the refusal. Witness: its
     seven unit tests.
   - **3b, how each source's hints stop being true (Round 3546).** A Hello's
     must carry a lifetime, since nothing withdraws it. Upstream scouts again
     at most every 8 s (`zenoh/src/net/runtime/orchestrator.rs`
     @ `const SCOUT_MAX_PERIOD: Duration = Duration::from_millis(8_000);`), so
     a live node's Hello is confirmed at least that often. A link-state hint
     may last until its withdrawal, since the flood is event-driven and the
     graph drops a node it no longer reaches; a full table still displaces a
     timed hint before it. A declared hint stays permanent.
   - **D4 on AP's autoconnect (Round 3546).** A node a discovery plane found
     (the gossip flood or a Hello) was dialled at its first dialable locator
     for no node, so Round 3542's D4 had a fourth path it did not name. The
     dial is now made for the node the intent names
     (`accept_loop::dial_decision`), as upstream's `connect_peer` dials each
     locator for its zid.
   - **3c, the directory on AP (Round 3548).** The face loop holds one
     (`accept_loop::LoopDirectory`, 512 rows). The loop dials a node by zid
     at two points: a discovery intent and the lifecycle opener's `AddNode`.
     Each first takes what it carries into the directory
     (`learn_locators`):
     - A Hello's locators are taken for `HELLO_LIFETIME_MS`, 42 s. That is
       RSVP's soft-state rule, L >= (K + 0.5) * 1.5 * R with K = 3 (RFC 2205,
       section 3.7), over upstream's longest scout period of 8 s.
     - A link-state read replaces the graph's earlier set for the node.
     Each then dials the node's candidates for its zid, so a node both
     planes found is tried at either one's locators, newest first. A node
     the graph lost is never dialled from a link-state hint it no longer
     carries, because every read of a zid is preceded by a link-state read
     for that zid. So the discovery channel carries no withdrawal, and no
     plane needs to send one. `AddNode` carries the graph's text, since a
     parsed locator cannot be spelled back. Witness:
     `accept_loop::tests::the_loop_dials_a_node_at_the_hints_its_planes_gave_newest_first`.
   - D3 is done for every source that has a producer. The declared source
     is in the directory and has none yet. A declaration that names a node
     by zid with its locators is D6's intent baseline, "the build-time
     declaration" of the peers a node should hold, and D6 confirms it into
     the directory as `Declared`. Upstream's `connect/endpoints` names
     locators, not nodes, so it stays a plain `Add`. The fixed-memory
     profile holds a directory when the MCU opener of step 6 reads one.
4. **D5.** The peer machine in SCXML and the bounded peer table; the AP
   `ConnectReconcile` desired set is replaced by it.
   - **5a, the machine and the table (Round 3550).**
     `sources/session/peer_connection.scxml` is the machine. SCE generates
     it into `out/wz-session-core/peer_connection_sm.rs`.
     - Its states are Idle, Resolving, Connecting, Established and Backoff,
       plus Refused, whose child names the cause: `NoLocator`, `NoSlot`,
       `IdentityMismatch` or `AuthorityRefused`. A refusal is therefore
       read as a state, and it holds until the next `open`.
     - `open` is `manual.start` (or `manual.refused` when the authority
       says no) and `close` is `manual.stop`. A second `open` or a second
       `close` has no transition and changes nothing, so D6's idempotency
       is the machine's shape.
     - No transition has a cond: the host classifies each outcome and
       raises the event that names it.
     - Each effect is a duty the host performs after the event: resolve,
       dial, arm or cancel the retry, abandon an attempt, close a session,
       and reset the retry schedule once a session is up.
     `wz_session_core::peer_table::PeerTable<N>` holds one machine per peer
     zid, with no allocator. It reuses an `Idle` entry when it is full, and
     refuses and counts only when every entry holds a peer the node is told
     to hold. The duty record the multicast machines kept privately is now
     `duty_outbox`, shared with this machine. Witness: the table's seven
     unit tests.
   - **5b, the nodes an `open` names, on AP (Round 3557).** The face loop
     no longer puts a lifecycle `open`'s node (`ConnectReconcile::AddNode`)
     into the desired connect-set. `apply_connect_reconcile` hands the node
     back, and the loop holds it by its machine. The host of the machine is
     `wz_runtime_tokio::node_peers` (`loop_peers` since 5c), a planner: each call returns the dials,
     retry waits and drops for the loop to take, so the lifecycle is reachable
     by a unit test.
     - The planner resolves from the loop's directory. It dials the node's
       candidate for its zid as a fresh face, and arms the node's retry on
       upstream's `connect/retry` schedule (`RedialSchedule`, now generic
       over the key). It starts the schedule over once a session is up.
     - The loop reports every end of a node dial:
       - established, and the face is held;
       - the node already held by another face, which then holds it;
       - no room under `max_sessions` or the measured ceiling (`NoSlot`);
       - another node at the InitAck (`IdentityMismatch`, decision D4);
       - any other failure, which backs off.
     - The loss of the face that holds the node is reported too, and the
       node is dialled again.
     - A node dial is held single-link.
     - `PeerTable` is generic over the peer's key and has `forget`. It
       removes an entry with no duty, upstream's shape for an endpoint a
       config write stops listing.
     Witness: `crates/wz-runtime-tokio/tests/node_peer_open_e2e.rs`, two
     real loops. The node's own zid is held. Another zid fails once at the
     InitAck and is not dialled again, where the desired set re-dialled such
     a node for ever. An unreachable node is dialled again on the schedule.
   - **5c, the configured endpoints, on AP (Round 3563).** The loop's
     desired connect-set is gone. A configured endpoint (the startup
     `connect/endpoints` and each reconcile of them) is a peer of the same
     table, keyed by its locator, so one machine kind holds every peer the
     loop is told to hold (decision D7: a target is a zid or a locator). The
     planner is `wz_runtime_tokio::loop_peers` (it was `node_peers`), keyed
     by `PeerKey::{Node, Endpoint}`, and gated as the connect reconcile is.
     - `fold_connect_reconcile` folds a request into a plan, and
       `LoopPeers::set_endpoints` applies it: an add opens each member, and a
       replace also forgets each member it leaves out. A forgotten endpoint
       is not dialled again, a session it holds is left standing, and a dial
       of it that is running ends unowned. Its retry growth goes with it.
     - An endpoint is dialled as written, for no node, and is retried on its
       own `#` retry span laid over `connect/retry`. It is named by its
       address, so one address listed twice is one endpoint; the startup list
       dialled each entry before, and a reconcile already named it once. Two
       links to one node come from two of its endpoints, as upstream's do.
     - Each retry timer carries the generation of its arming. A timer whose
       arming is no longer its peer's (the peer was forgotten, or reached
       another way) dials nothing; the timer of the old address-keyed re-dial
       had no such guard and was a sleep inside the dial itself.
     - One face can hold several peers. An endpoint whose dial meets a remote
       already held (a gossip dial reached it first, or its multilink link
       joined that session) is held by the face that holds the remote, and is
       lost and dialled again with it. The address index that kept a gossip
       dial and an endpoint dial apart is gone.
     - With `max_links > 1` an endpoint's dial aggregates, and a reconcile's
       does too (it dialled single-link before). The link stays the per-link
       re-add's; the endpoint is the machine's, and the session's collapse,
       which the re-add does not answer, is now reported to it. A link the
       session refuses for its key is a failed dial.
     Witness: the planner's ten unit tests, the reconcile arity test on
     the planner, and `router_redial_backoff_e2e`, whose removal and re-add
     now arrive together, after which the endpoint's first retry is the
     initial wait. Layer E7b's re-dial witness now reads the dial itself (a
     face that failed at the dropped router's address) rather than a log
     line announcing one, and the multilink dial-side fixture dials its
     node at two endpoints.
   - D5 is done on AP: every peer the face loop is told to hold, by zid or by
     locator, is held by its machine. The `close` verb reaching the machine
     as `manual.stop` is D6's.
5. **D6.** Intent and status, `reset` with a generation, and the status GET.
   - **6a, close withdraws and reset is once per generation (Round 3579).**
     The close and reset verbs are queries (`wz_session_core::lifecycle_query`),
     where a reply says what was done.
     - A close takes the peer out of the intent before it orders the
       sessions closed. The intent is a port, `PeerIntent`, apart from the
       sessions' `SessionDirectory`. On AP the face loop's reconcile channel
       implements it: `ConnectReconcile::Withdraw` reaches
       `LoopPeers::withdraw`, which stops every machine that holds the node
       (`manual.stop`). That is the node's own machine and each configured
       endpoint's whose last session reached it. An endpoint has no zid of
       its own, so the planner keeps the zid each peer's last session named.
       A held session is closed by the machine's `close_session`, a running
       dial is dropped, and a wait is cancelled, its timer's generation no
       longer the peer's. The machine stays `Idle` until an `open` or a
       connect-list edit names the peer again.
     - `reset/<generation>` is the one verb whose key carries an argument,
       and the grammar (`LifecycleKey::parse`) says so, so a seven-chunk key
       of any other verb is still refused. The answerer keeps the latest
       generation taken per peer. A generation no later than it answers
       `duplicate` and closes nothing; a later one orders the sessions closed
       and leaves the intent, so the peer's machine backs off and dials
       again. A generation is taken even when no session was found, so its
       retransmission after the peer is back closes nothing.
     - The authority gains `admits_reset`, defaulted to refuse. The
       capability document lists `close` and `reset`. The ap-demo router hands
       its reconcile sender as the intent; the peer host has no run-time
       intent and says `NoIntent`.
     Witness: the reset and close-withdraw tests of `lifecycle_query`, the
     grammar's reset arm, the planner's two withdraw tests, and
     `node_peer_open_e2e`'s withdrawn node: one face, closed by the
     withdrawal, and none after it, where the retry wait is a tenth of the
     run.
   - **6b, the status GET (Round 3592).**
     `@/<zid>/<whatami>/session/status/<peer-zid>` is the fourth lifecycle
     query, and it only reads.
     - The reply holds the links of the node's sessions with the peer, open
       or with a close ordered (`SessionDirectory::links`, the enumeration the
       close uses), whether the peer is in the intent, and the state of each
       machine that holds it. A refusal state carries its cause, and an
       endpoint's machine carries its endpoint.
     - A machine's state is spelled in one place,
       `PeerConnectionState::words`, matched without a wildcard. The intent is
       `PeerConnectionState::in_intent`: every state but `Idle`, the state a
       full table already treated as free.
     - The machines are a port, `PeerMachines`. On AP the face loop owns them
       and changes them on every dial, loss and timer, so it publishes. After
       each planner call it replaces a `PeerBoard`, which the host made and
       handed to the loop (`FaceSources::peer_board`, the shape of the session
       ceiling), and the query reads the board. An endpoint is read by the zid
       its last session named, and one that never reached a node is on no
       board.
     - The authority gains `admits_status`, refused by default. A host with no
       machines (the peer host) answers from its sessions alone, with no
       machine and the peer out of the intent. The capability document lists
       `status`.
     Witness: the status tests of `lifecycle_query` and of
     `session_close_query` (a real session's link read open, then closing
     after a close), the planner's board test, the table's state-words test,
     `node_peer_open_e2e`, whose four runs read the board the real loop
     published (held, withdrawn to `idle`, refused with
     `identity_mismatch`, waiting to dial again), and Layer E6's status GET
     between two `wz-ap-demo` peers.
   - **6c, open as a query (Round 3597).**
     `@/<zid>/<whatami>/session/open/<peer-zid>` is the fifth lifecycle query.
     It asks the node to hold the peer, so the peer joins the intent and its
     machine connects, and it answers that the request was taken
     (`{"verdict":"opening"}`), not that a session is up: the status query
     reads how the dial ends. A second open of a held peer changes nothing and
     says the same, which is what makes a retransmission safe.
     - The opener is a port, `PeerOpener`, apart from the sessions, the
       intent and the machines. `LinkstateOpener` implements it and also the
       in-band `SessionOpener`, over one `ask`, so the Push and the query make
       one request (decision D7). The port answers with an outcome, not a bool,
       so the reply says which refusal it was: the key is not a zid, the node
       holds no locator for the peer (`peer_unknown`), it holds locators none of
       which can be dialled (`no_dialable_locator`), or the loop is gone
       (`opener_gone`).
     - A router keeps one graph per region, so the opener reads the routers
       region's graph and each peers region's (`NodeLocators`, minted by the
       forwarder), and asks for a node at the locators of every graph that
       holds it, each once. The peer host has no loop channel to ask through
       and passes `NoOpener`: it serves no open query and lists no `open` verb,
       since the capability document says what the node has bound.
     - Decision: a peer the node has no locator for is refused at the opener
       and does not enter the peer table, which is bounded and keeps a refused
       peer until the next `open`; a run of opens for zids nobody advertised
       would otherwise fill it. The cost is that a locator the loop's directory
       learns later, from a `Hello`, is not found by an open the graphs could
       not place. D5's `no_locator` refusal stays the machine's for a locator
       that expires after the open. Whether an open should enter the table first
       is open (section 5).
     Witness: the open tests of `lifecycle_query` (each outcome its own word, a
     refused or pattern key asking the opener nothing, no opener serving
     nothing), `LinkstateOpener`'s query-form outcomes, its two-graph union and
     the join from the query key to the loop's dial request, and the loop's own
     handling of that request, `node_peer_open_e2e`.
6. **The MCU opener** over `SessionHost`, `wz-session-lwip` forwarding the
   feature, and a witness on the fixed-memory image.
   - **The opener is the same host as AP's, so the host is written once
     (decision, owner, 2026-10-25: the structure that is right in the long
     run, whatever it costs).** The connection machine of D5 was already
     shared. What AP's face loop did around it (which face a dial opened,
     which peer each held face is held for, which retry timer is still its
     peer's, which zid a peer's last session named) is the machine's host, and a
     fixed-memory node needs the same host without an allocator. Two copies
     would drift, so the bookkeeping moves down into one.
   - **6.1, the planner, once for every profile (Round 3604).**
     `wz_session_core::peer_planner::PeerPlanner<K, I, N, D>` is `LoopPeers`'
     bookkeeping in fixed-capacity tables: `N` bounds the peers, and with
     them the held faces, the armed timers and the remembered zids (one per
     peer each), and `D` bounds the dials in flight together with the ones a
     peer stopped wanting while they ran. It builds for `thumbv7m-none-eabi`
     with no allocator.
     - What differs between profiles is a port, `PeerPorts`: what a peer is
       dialled at, the next retry wait, and starting the schedule over. AP
       answers them from its loop's directory, its configured endpoints and
       `RedialSchedule`. The planner mints a dial's face from the counter the
       host gives it, and hands its actions to a sink the caller gives, so no
       output size is guessed.
     - A dial the planner has no room to track is not made: the machine is
       told the host has no slot, which it already refuses by (`NoSlot`).
     - A peer is one session, so the planner holds one face per peer (the
       primary's, for a session of several links), and a face can hold several
       peers. That bounds the table by the peers, with no overflow to decide.
     - `wz_runtime_tokio::loop_peers::LoopPeers` is the AP wrapper: its
       endpoints, its retry schedule, the directory lookups and the log lines.
       Its public surface is unchanged.
     Witness: the planner's eight tests over a fake host (dial, hold, loss and
     retry; a refusal; a stale timer; a released and an abandoned dial; one
     face holding two peers; a withdrawal; the machines read with their zid; a
     dial the planner cannot track), `LoopPeers`' own thirteen, which now run
     through it, and `node_peer_open_e2e` and `router_redial_backoff_e2e`
     unchanged.
   - **6.2a, the fixed-memory host is the connect manager, on the planner
     (Round 3613).** The fixed-memory profile already had a host for peers
     it dials: `wz_session_mcu::connect_manager::ConnectManager`, one row per
     configured endpoint, a retry schedule per row and a dialer port
     (`SlotDialer` over `SessionHost::dial` on the slot profile). It predates
     the machines, as AP's desired connect-set did, so it is rebuilt on the
     planner the way D5c rebuilt AP's. The MCU opener is therefore not a
     second host: it is this manager, with nodes held by zid beside the
     endpoints (6.2b).
     - Its surface and what it promises outside are unchanged. An endpoint the
       list drops is hung up. One the build cannot dial is refused and not
       retried until the list is written again. Failures before a session is
       up are one outage and grow the wait; a session that was up and drops
       starts the schedule again.
     - An endpoint is a peer keyed by its text, so one written twice is one
       endpoint, as on AP. What the build cannot dial is a peer with no
       candidate (`NoLocator`); the reason the node reports at
       `status/connect` (`unsupported`, `bad_address`, `multi_link_group`) is
       read off the dialer when asked, not stored.
     - The `Dialer` port gains three questions with defaults, so a dialer that
       answers none behaves as before: what it cannot dial (`classify`, asked
       before any dial), whether a session is up (`established`) and which node
       it reached (`remote`). `UdpDialer` and `SlotDialer` answer all three. A
       dialer that does not say when a session comes up is told of at its end,
       as established and then lost, which gives the same schedule.
     - The planner gains `stop` for one key, and its close action and `withdraw`
       are no longer behind the lifecycle seam: a host that stops holding a
       peer it dialled hangs the session up with no verb in the build.
     - No call of the manager is its own callee: a dial that does not start is
       reported in the next turn of a loop, because the stack gate reads the
       worst chain of direct calls under a tick and a cycle is no bound.
     Witness: the manager's eight tests (the five it had, and a session seen up
     and then lost, a dropped endpoint with a session up hung up and dialled
     afresh on a rewrite, an endpoint written twice), `wz-session-mcu`'s own
     suite and clippy over all features, the slot-profile shape for the
     bare-metal target, and the lwIP slot admin node test.
   - Repair of 6.2a (stack): the manager had taken the planner's tables
     inside itself, and on the Zephyr image the manager is a local of the
     node's run function, so about 14 KB of peer tables and machines sat on
     a 9216 B main-thread stack. The tables now live in a `PeerStore`, a
     static the image owns beside the rest of its node storage, and the
     manager holds a reference to it (`ConnectManager::in_static_store`);
     only the heap build boxes its own. The peer machine declares
     `sce:capacity="2"`, because the host raises one event at a time and
     nothing in the machine raises or sends, so its queue is 16 B instead of
     the engine default. A test holds the bound: the store is over 8 KiB and
     the manager under 4 KiB. The Zephyr stack figure can be read only on
     the hosted run; the image edit there is not buildable here.
   - 6.2b-1, the nodes held by zid beside the endpoints, in the same manager.
     A peer is keyed by an enum, an endpoint by its text or a node by its
     zid, so the one table, the one planner and the one retry schedule serve
     both, as the AP loop's `PeerKey` does. A node is dialled at the first
     live hint of the locator directory (D3) that the build can dial, FOR its
     zid: the dial target carries the zid, the dialer's `dial_for` makes a
     session whose handshake closes at the InitAck when another node answers
     (D4), and the manager hangs up a session that comes up naming another
     node whatever the dialer let through, which the machine reads as an
     identity mismatch and does not dial again until the node is opened. The
     port refuses by default: `Dialer::VERIFIES_NODES` is false, and a dialer
     that does not say so opens no node, because a session to whichever node
     answers a stale hint is not a session to the zid. The slot dialer says
     so, since the slot host already took the expected zid; the heap UDP
     dialer says so too since the round after 7d (`dial_for` sets
     `expect_peer_zid` on the session's actions before the session is
     spawned, the same call the slot host makes, so the InitAck of another
     node closes it `Invalid` before any OpenSyn; its test dials three
     acceptors, all node `a1`, for `a1`, for another zid and for no node).
     A peer's name is an identity and not a copy of what it names: seventeen
     bytes, an endpoint's row slot or a node's zid, where the endpoint's text
     is sixty-four and more. Round 3613 keyed the machines by that text, and
     the planner holds a name in every table, in every action and in the sort
     of a `withdraw`, so the frames the dial passes through under the node's
     loop carried several copies of it: the Zephyr kit's worst chain read
     8900 of 9216 bytes with the manager's dial in it. The action now names the
     peer and nothing else, and the dial reads the locator where it lives (the
     endpoint's row, or the directory's hint) when it is made, out of the
     critical section. Read off the lwIP fixed-memory image for the bare-metal
     target, the frames of the manager's own methods fell (the one that takes
     an action list from 1184 to 368 bytes, the planner's step from 600 to 200)
     and the sort of names, which this step would have grown to 3544 bytes, is
     912; the Zephyr figure is read on the hosted run.
     The cost is a limit, `MAX_PEER_NODES`, whose default is 0: a node is a
     machine of some 930 bytes and its share of the tables, and an image that
     is never asked to open a peer by its zid declares none of it. The
     directory is sized at two hints per node and lives in the same store, so
     it is under the one critical section the planner is. An open that cannot
     be served takes no row, so a flood of opens for zids nobody advertised
     does not fill the table: no room, no hint, or no hint this build can dial,
     each by its own name (`NodeRefusal`). Tests that hold nodes run in a leg
     that states two (`C1m mcu peer nodes`); under the default they assert the
     refusal for want of room.
   - 6.2b-2 (landed): the request to hold a node by its zid, made where the
     manager is not (`NodeOpener`, from `ConnectManager::node_opener`, which a
     static store has). A query a node answers is served beside its loop, so
     the opener answers at once with what the node knows without the loop (can
     this dialer verify a node, is there room, is there a live hint, can this
     build dial one), keeps a request that passes in the store, and the next
     tick holds the node. The store also mirrors the nodes the manager holds,
     so an open of a held node is the same open and does not ask for room. What
     a build can dial is now asked of the dialer TYPE (`Dialer::classify` takes
     no `self`): the opener holds no dialer, which the manager owns, and the
     fact was always the build's. How a refusal is said (decision): the open
     outcome and the refused reasons gain two words, `NoRoom` (the node holds
     as many peers by their zid as it was built for) and `Unverifiable` (its
     links do not hold a session to the node a dial was made for), because
     each is a different thing an operator can do something about and neither
     is a missing locator. `NodeRefusal::NoLocator` is `PeerUnknown` and
     `NoDialableLocator` is itself. The mapping onto `OpenOutcome` is not in
     this crate: `lifecycle_query` is compiled only with an allocator, and the
     fixed-memory profile has neither it nor the in-band switchboard
     (`drive`, same gate), so the verbs there need the query's wire written
     without `alloc`, which is the next piece, not a mapping.
   - 6.2b-3 (landed, first half): the open query on the fixed-memory profile.
     Decision: the vocabulary is split from the heap, not the query ported.
     `lifecycle_wire` (always compiled, no allocator) holds what a verb says:
     the open verdict, the refused reasons, the open key and the capability
     document; `lifecycle_query` re-exports it, so the heap profile's paths and
     words are unchanged, and the zid a key spells is read by one function in
     `credential_identity` that `zenoh_hex_to_zid` now calls. The node's admin
     queryable (`host_admin_queryable_fixed_with_open`) answers
     `GET @/<zid>/<whatami>/session/open/<peer-zid>` for a literal key that
     names this node, its role and one peer, in the heap profile's words, from
     the arena at zero allocations (`NodeOpening`; the node's own is
     `ControlledOpener`, the manager's `NodeOpener` under the node's write
     permit, with `NodeRefusal` mapped onto the open outcome), and the
     capability document `session/verbs` lists `open`, which is all this
     profile binds. Close, reset and status stay on the heap profile: a close
     walks a table of sessions a host lists, reset keeps a record per peer, and
     the status document is a list of machines, and none of them is what the
     question was. The Push form of a verb (the in-band switchboard) is not
     bound here either.
   - 6.2b-4 (landed, first half): the two fixed-memory admin images bind the
     verb (the lwIP bare-metal one and the Zephyr one). The opener is no longer
     typed by the dialer: what the dialer can do (whether it holds a session to
     the node it dials for, which locators it can dial) is written into the
     peer store by the manager when it is made, so `NodeOpener::in_store` and
     `ControlledOpener::new` are `const` and an image declares its opener in a
     `static` beside the store and the control, before any manager exists; until
     there is one the opener says `Unverifiable`. Each image declares it as a
     `static` of its own and not a member of its table of statics, because the
     opener holds references: a table whose initial value is not all zero
     bytes moves from `.bss` into `.data` and takes a copy into flash (the
     Zephyr image's `Statics` says what that cost once, 131 KB), and for the
     same reason the store's classification is an `Option` of a function and
     not a function. At the default `MAX_PEER_NODES` of zero the images answer
     the open `refused` for want of room, by name, which is the honest answer
     of a node that was built to hold none; a build that states more, and has
     hints, holds the node. The lwIP image builds, and the no-allocator link
     gate holds it; the Zephyr image is read on the hosted run.
   - 6.2b-5 (landed, first half): a node held by its zid is a session of the
     node like any other. It was dialled and held, but nothing declared the
     admin space on it and no node reported it: the slot node and the slot
     client read the manager's `sessions()`, which is the endpoints' (and
     must stay so, since the status pairs it with `states()` by position).
     `ConnectManager::node_sessions()` is the nodes', and both read it beside
     the others, so the open of a node ends in a session whose declarations
     went out and which the admin root lists. The node (`SlotAdminNode`)
     gains the build's source of hints, `declare_node(zid, locator)` (a hint
     is where the zid may be, kept until the node is given another table),
     `open_node`, `node_opener`, and `for_each_dialled_node` /
     `for_each_node`. Witnessed on the lwIP loopback with two nodes: B,
     built with room for two nodes, is told A's locator, refused a zid it has
     no hint for (`NoLocator`), opens A by its zid, dials it FOR that zid,
     and both report one session (leg `C1m admin node slot nodes`).
     Decision: `wz-session-lwip` needs nothing forwarded (it re-exports the
     manager's module whole, and the images build over it).
   - Not done in step 6, and why. The Hello source of hints: no scouting
     receive exists on the fixed profile (the slot node never reads a Hello),
     so it waits on the scouting work on the cooperative engine and is that
     track's to hand over. The witness on a built image: it is a step of the
     lane (`admin_node_verdict.py`), whose grammar the board shares, so it is
     the lane owner's to agree (an image built with room for one node and a
     declared hint for the peer the lane runs, an open by its zid, then the
     admin root's `sessions[]` read). The node's STATE (`NodeState`) is not in
     the status documents: the heap profile has a status verb for it, the
     fixed profile has none, and the sessions row is what an operator reads.
7. **D7** transports 2 and 3 as values of the build configuration axis.
   - **The structure (decision; the owner delegated the choice on
     2026-10-26 with "cost ignored, the most correct long-term, textbook,
     ultimate"; 7a to 7d are landed; where what landed differs from
     the first draft below, the paragraph after the steps says how).**
     - The contract is the port the fixed profile already has,
       `NodeOpening` (open a peer by its zid, answered with an outcome and
       not a bool). The three transports differ only in what feeds the
       port, so no transport owns a copy of the semantics.
     - By `docs/build-configuration.md` C2 and C3 a switch that adds code is
       a capability, an additive cargo feature, and a choice is an axis.
       Transports 1 and 2 add code, so each is a capability:
       `lifecycle-open-query` (in-band: the `session/open` leg and the
       `session/verbs` document of `admin_fixed`) and `lifecycle-control`
       (out-of-band: a control port that maps an agent's commands onto
       `NodeOpening`, idempotent because the port is). Transport 3 is the
       absence of both. The axis, `lifecycle-transport` with the options
       `in-band`, `out-of-band` and `declared`, is what an image selects, and
       each option's `cargo_rule` adds its capability. An axis holds one
       value, so an image has one transport; a host that tests every
       transport builds the capabilities it needs.
     - The declared intent is a node declaration's, since D6 puts the
       intent's baseline in the build: `[[endpoint]]` with `role = "peer"`,
       a zid and the locators it may be found at, checked as the other
       endpoints are (a count above `MAX_PEER_NODES` is refused by name).
       The node confirms each into its directory as `Declared` and holds it
       by its machine, which is all transport 3 does.
     - Steps. 7a: gate the in-band leg behind its capability in
       `wz-session-mcu` and forward it through `wz-session-lwip` and the
       images, with the gates that census a feature fed in the same commit;
       the `declared` value then carries no `serve_open`. 7b: the axis in
       `deploy/wz-config.toml` and its generated Kconfig. 7c: the declared
       peers in `wz_node.py`. 7d: the control port, and its agent in the
       host that hosts the node.
     - What landed, and how it differs from that draft.
       - **7a is a type, not a feature.** The in-band verb is not a cargo
         feature: `docs/build-configuration.md` C3 says a choice that changes
         the shape of the code is a type parameter, monomorphised at no
         run-time cost, and a feature would also have been a new atom of the
         catalog (open question below). `admin_fixed`'s queryable is generic
         over `NodeOpening`, whose constant `BOUND` is false only for
         `NoOpening`; the answer serves `session/open` only if `BOUND`, so the
         third transport's image carries none of that code. The capability
         names above stay the vocabulary, as the types the images name.
       - **7b** is the axis `lifecycle-transport` of `zephyr-admin-node` with
         `in-band` (the default) and `declared` (selectable on the fixed
         admin node over lwIP), and the image selector `lifecycle-declared`.
         `out-of-band` is declared with its control port in 7d and not
         before: an option that cannot be built is not declared. The
         no-allocator gate carries the declared build as a row, clean.
         What the value saves, measured on pc2 as the sum of the text
         symbols of the LTO staticlib (`llvm-nm -S`, the gate's two fixed
         admin node builds, thumbv7em, release): 288,386 B in-band and
         286,096 B declared, so 2,290 B. It is the archive's code, not the
         linked image's `.text`, which the Zephyr link and its garbage
         collection decide.
       - **7c** is two halves. The node: `ConnectManager::hold_declared` hints
         each `DeclaredPeer` (`Declared`, permanent) and opens it by its zid;
         `ClientNode` takes the list and stops at start, naming the peer,
         when one cannot be held (exit 4), since a node that silently lost a
         peer it was built to hold would run and be wrong. The declaration:
         `[[endpoint]] role = "peer"` with a `zid` (the text zenoh prints, as
         `zid_from_key_text` reads it) and a `tls/` locator, because a plain
         stream cannot prove the node that answered is the one the zid names
         (D4): a dialer that does not verify refuses it `Unverifiable`.
         Each peer is a session of the node and raises `MAX_PEER_NODES` when
         the declaration states none. Witness: the manager's test of the
         declared list, `wz_node.py --selftest`, and the declared node
         compiling over the generated table. Not run: a declared node holding
         a declared peer over a real secure channel.
       - **7d is a port, a line protocol and an agent, and not an axis value.**
         The three transports share one function. `node_opening` (a module of
         its own, no feature gates it) holds `NodeOpening`, `NoOpening` and
         `open_verdict`: the permit, the spelling of the zid, the outcome and
         its words, written once. The in-band `session/open` leg of
         `admin_fixed` was changed to call it, so that no transport owns a copy
         of the semantics, and its test (5) did not move. `control_port` is the
         out-of-band transport over it: one line is one command, `open <peer>`
         (the peer as a key spells it), and one command is answered with one
         JSON object, the verdict `session/open` answers or an error word
         (`unknown-command`, `open-takes-one-peer`, `line-too-long`) for a line
         that is no command and so names no peer. Repeating `open` is safe
         because the opener is idempotent. The channel is the host's:
         `wz_runtime_posix::control` reads standard input without blocking (one
         `poll(2)` a round) in a fixed buffer, and `host-slot-node`'s `control`
         feature wraps the node's application in `WithControl`, whose opener
         permits what the pipe asks, since whoever holds the pipe started the
         node. Both host binaries take it (`host-slot-node`, `declared-node`).
       - **`out-of-band` is not a value of the axis `lifecycle-transport`.**
         The axis belongs to `zephyr-admin-node`, whose image has no agent
         channel (no standard input), so the option could not be built there,
         and an option that cannot be built is not declared. It is a feature of
         the host that hosts the node, which a test agent builds with, as the
         draft above said for a host that tests every transport. The axis keeps
         its two values.
       - Witness of 7d: the unit tests of the three modules (5 and 5 in the
         crate, 4 in the posix seam), and `deploy/host-slot-node/tests/
         control_channel.rs`, which starts the node as a process, writes lines
         to it and reads the answers (2). The node there is built for no peers
         by their zid, so a well-formed request is refused for room; the answer
         is the in-band one, repeated. Not run: an out-of-band open that
         succeeds, which needs a build with room and the secure channel
         (decision D4), the same gap as 7c's.

## 5. Open

- The out-of-band remainder. D7 says the transport maps each command onto
  the contract, and step 7d built one command, `open <peer>`, because the
  port it maps onto, `NodeOpening`, is open-only on the fixed-memory profile
  (6.2b-3 left close, reset and status on the heap profile). Three things of
  D6 and D7 are therefore not reachable out of band, and none is scheduled:
  `close` and `reset <generation>` (the generation is what keeps a
  retransmitted reset once); reading a peer's state (the status document of
  D6) and the node's own zid, which an agent needs to know which node it
  drives; and a locator target with no expected zid, which D7 admits "when
  the authority admits locator targets" and which the fixed profile has no
  path for (a plain stream is refused `Unverifiable`, D4). A control channel
  whose owner holds the pipe is such an authority, so the third needs a
  decision on who the authority is there. Close, reset and status need a
  port beyond `NodeOpening` on the fixed profile, which is a design step
  before it is a command.
- Whether a node may be told to open a session as the accepting side (a
  listen intent). The contract of D5 and D6 has the dialling side only; adding
  the other changes the contract, so it is the owner's ruling.
- Whether the feature catalog records this scope as a regrade of
  `session-close-ingress` or as a new atom. Round 2697 regraded that atom when
  item 761 widened it; this is the owner's ruling either way.
- Whether a Push on an `@/` key reaches a zenohd plugin's subscriber. The
  router routes `@/` keys as admin space; not measured.
- Whether upstream zenoh admits a pinned self-signed certificate with name
  verification off as D9 uses it. Not measured.
- The memory and handshake time of D9's channel on the fixed-memory profile,
  including how far the record size limit (RFC 8449) shrinks the 16 KiB
  record buffers. Not measured.
- Whether an `open` for a peer the link-state graphs do not hold should enter
  the peer table and let its machine refuse with `no_locator` (D5), rather than
  be refused at the opener (step 6c). The first lets a `Hello` the loop's
  directory learns later satisfy it and shows the refusal in the status read;
  the second keeps a flood of opens from filling the bounded table. Neither is
  measured, and a table that reclaims a refused entry would allow both.
