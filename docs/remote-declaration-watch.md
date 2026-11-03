# Remote declaration watch

`remote-declaration-watch` (capability, off by default, `WZ_CAP_REMOTE_DECLARATION_WATCH`) names
the peer a declaration event came from. It is wz's own: no upstream library reports it, so it is
off in every original.

## The problem it answers

A declaration listener (`declare_remote_subscriber_listener`, `declare_remote_queryable_listener`,
`declare_remote_token_listener`) is told what the peer declares, and a session is one link, so the
peer is whoever the session is connected to. That is enough while the listener never outlives the
link. A session that reconnects can meet another peer, and a listener that keeps its callback
across the gap gets events from two peers under one registration. Reading `Session::peer_zid()` in
the callback is not an answer: by the time the callback runs, the link may have been replaced, and
the reading cannot be ordered against the event.

So the identity travels with the event. It is read when the event is staged, in the dispatch that
carries it, and the deferred callback receives it as data.

## What a listener sees

Every `DeclEvent` carries `peer`, read with `DeclEvent::peer()`: the zenoh id the session learned
at the handshake, the same bytes `Session::peer_zid()` returns, as `Option<&[u8]>`.

* `Declared`, `Undeclared` and `Synced` (`docs/declarations-synced-event.md`) all carry it. The
  final of the initial interest is the peer's, and so is the id on it.
* A session that reconnects to another peer reports each event under the peer it came from: the
  first establishment's events name the first peer, the next one's name the second.
* `None` in a build without the capability, and when the session holds no identity at the moment
  the event is staged.

The three variants are `non_exhaustive`, so a later field is not a break for a matcher that
already writes `..`.

## Where it lives

* `wz_runtime_tokio::session::decl_listener`: `Session::peer_reading` builds the reading each
  staging sink holds. It captures the session's link actions only under the feature, and reads
  `peer_zid()` when the sink runs, which is under the observer lock. The identity is a leaf lock
  of the session, so the read cannot deadlock with the dispatch.
* The capability is a feature of the runtime and passes through `wz-capi-core`. It needs no
  feature of the session core: the identity is the session's, not the observer's.

## What it costs

Nothing without the feature: the field exists and holds `None`, no link actions are captured and
no identity is read. With it, a listener's sinks hold one reference to the link actions, and each
event copies the 16 bytes of the identity.

## Not yet

The unicast host session only. A multicast session has many peers and no single identity; the
router's face names its peer by its own means. The C ABIs have no door for declaration events at
all, and a capability that exports one is a separate step, which will carry this identity with it.
