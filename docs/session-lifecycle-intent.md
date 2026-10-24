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
   failure.
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
     `wz_runtime_tokio::node_peers`, a planner: each call returns the dials,
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
   - Left of D5: the configured endpoints move from the desired set to the
     table, keyed by endpoint (`forget` is their removal). The `close` verb
     reaches the node's machine as `manual.stop`; that is D6's intent.
5. **D6.** Intent and status, `reset` with a generation, and the status GET.
6. **The MCU opener** over `SessionHost`, `wz-session-lwip` forwarding the
   feature, and a witness on the fixed-memory image.
7. **D7** transports 2 and 3 as values of the build configuration axis.

## 5. Open

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
