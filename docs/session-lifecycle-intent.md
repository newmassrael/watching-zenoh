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
  36,736 B on `thumbv7m-none-eabi` (`deploy/session_slot_bytes.json`).
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
2. **D4.** The expected zid on every dial path. Done when a dial to a locator
   that answers with another zid closes at InitAck on AP, the C ABI and the MCU
   host.
3. **D3.** The directory and its three sources, with expiry.
4. **D5.** The peer machine in SCXML and the bounded peer table; the AP
   `ConnectReconcile` desired set is replaced by it.
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
