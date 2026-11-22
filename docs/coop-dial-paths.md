# Dial paths of the cooperative engine

Every dial the cooperative engine (`wz-capi-coop`'s `CoopEngine`) makes, for the dial role's
face and for a face attached later, goes through one call: `Core::begin_dial`
(`crates/wz-capi-coop/src/engine.rs:1698`, called at `:1892` and `:3220`), which asks the links
for `SessionLinks::begin_initiator` while the session is held. The engine never waits for the
answer: the dial is kept as `Link::Dialing` and asked again (`PendingDial::poll`) at each step
(`engine.rs:2095`), at most `DIAL_LOOK_MS` apart (`engine.rs:317`, `:2764`), and given up at the
open deadline (`open_deadline_us`, `engine.rs:1875`: `open_timeout_ms` on the session's clock),
which also bounds the zenoh handshake that follows. A redial waits `redial_ms` counted from the
end of the failed dials (`dial_or_wait`, `engine.rs:1956`), whatever link kind failed.

So a dial path holds the session only for as long as its `begin_initiator` and each `poll` take.
A path whose `begin_initiator` is the trait's default (`session_drive.rs:570`) makes its link with
`open_initiator` inside the call and answers it at the first `poll` (`Dialled`); that is right
only for a link whose open does not wait. The table below is every path, the links that reach it,
and what it waits for while the session is held.

| Path | Links | Waits under the session? | How |
|------|-------|--------------------------|-----|
| `tcp/` over host sockets | `IpLinks` with `PosixTcpDial`, `WindowsTcpDial` | no | non-blocking connect, asked for writability |
| `tls/` over host sockets | `IpLinks::with_tls` (`TlsDial`, `HostTls`) | no (this change) | connect begun, then one handshake step per ask |
| `udp/` over any `IpLinks` | host, Zephyr | no | binds a socket; nothing to wait for |
| `tcp/`, `udp/` over the program's transport | `AppLinks` | no (this change) | the program is asked; its report is polled |
| `udp/` over lwIP | `LwipLinks` | no | binds a socket; `tcp/`, `tls/` unsupported |
| `tcp/` over lwIP's raw API | `LwipTcpDial` in an `IpLinks` | no (this change) | SYN handed to lwIP, one poll per ask |
| `udp/` over Zephyr | `ZephyrLinks` | no | binds a socket; `tcp/` unsupported |
| `tcp/` over Zephyr sockets | `ZephyrIpLinks` (`ZephyrTcpDial`) | **yes** | blocking `connect`; see below |
| in-memory pair | `MemoryLinks` (`wz-session-mcu`) | no | a pair of queues |

No other link kind is dialled: `LinkProto` is `udp`, `tcp` and `tls` alone
(`session_drive.rs`), and a locator of any other scheme is refused before `begin_initiator`.
Joining a multicast group (`open_group`) and taking connections off a listener are not dials and
are not covered here.

## `tcp/` over host sockets

`IpLinks::begin_initiator` (`crates/wz-runtime-coop/src/ip_stack.rs:543`) claims the link's buffers,
begins the connect (`StreamDial::dial_started`: `PosixTcpSocket::connect_started`,
`crates/wz-runtime-posix/src/stream.rs:93`; the Windows twin at
`crates/wz-runtime-posix/src/windows/stream.rs:84`) and returns a `PendingStream`
(`ip_stack.rs:625`) whose `poll` asks `StreamSocket::connected` (`stream.rs:349`): writability with
a zero timeout, then `SO_ERROR`. Witnessed by `crates/wz-capi-coop/src/tests/dial_in_flight.rs`.

## `tls/`: connect, then the handshake one step per ask

Before: the `tls/` branch fell to `open_initiator`, so `TlsDial::dial`
(`crates/wz-tls-mbedtls/src/stream.rs:564`) ran under the session a blocking connect and then the
whole handshake, waiting up to `HandshakeBudget::DEFAULT` (100 waits of 100 ms, ten seconds) for
the peer's records. A peer that took the connection and never answered held every other caller
of the session for ten seconds per dial.

Now:

- `IpLinks::begin_initiator` begins a `tls/` dial as it begins a `tcp/` one, with the channel's
  `dial_started` and a `PendingStream` that makes an `IpDriver::Tls` once the stream is made
  (`MakeLink`). The buffers are claimed at the begin and go back with a refused or abandoned dial.
- `TlsDial::dial_started` (`stream.rs:602`) makes the session under the policy (a policy that
  cannot make one is still refused before any connect) and begins the connection under the channel
  with the wrapped dial's `dial_started`; nothing waits.
- `TlsStream::connected` (`stream.rs:193`) is the state machine: `Connecting` asks the stream under
  it; once that is made, `Handshaking` runs one `Session::handshake` step per ask, and a step that
  wants to read (or write) answers `Ok(false)` and is taken up at the next ask; once done, the peer
  is named under the policy as the waiting dial names it, and the stream is `Open`. A connect the
  stack refuses is `TlsStreamError::Transport`, a handshake that fails or a peer the policy does not
  accept is `TlsStreamError::Tls`; either is `LinkOpenError::Refused` to the engine.
- `HostTls::dial_started` (`crates/wz-capi-coop/src/tls.rs:289`) forwards to the channel's, telling
  the roots the time first as its waiting dial does; without it the trait's default would have run
  the waiting dial.

The deadline of a begun handshake is the engine's open deadline, not the `HandshakeBudget`, which
now bounds only the waiting `TlsDial::dial` (still used where a stack opens a link outside the
engine). An over-the-wire stall is therefore given up after `open_timeout_ms`, together with the
zenoh handshake, instead of after ten seconds of TLS alone.

What a step still does under the session: the crypto of that step (the key share of the first
flight, the peer's signature and chain, the key schedule), which is CPU and not a wait, and the
write of the records the step produced through `Lower::send` (`stream.rs:45`), which waits until
the stream took them. A fresh connection's send buffer takes a handshake flight whole, so that
write does not wait in practice. The accepting end (`TlsListener::accept`, `stream.rs:728`) was
already stepped one handshake step per accept and is unchanged.

Tests: `crates/wz-tls-mbedtls/tests/dial_started.rs` (a silent peer leaves twenty asks under one
second with the ClientHello sent; a peer that answers completes over several asks and the stream
then names it and carries bytes; a closed port is refused; an untrusted chain fails as the
channel's error), `a_heap_tls_dial_is_begun_and_asked_never_waited_for` in `ip_stack.rs` (the
begun dial answers nothing while the channel opens, holds and returns its buffers, never calls the
waiting dial) and `a_begun_dial_meets_the_listener_on_one_thread_and_no_roots_refuse_it` in
`crates/wz-capi-coop/tests/tls_provider.rs` (both ends stepped on one thread). The engine-level
`crates/wz-tls-mbedtls/tests/engine_tls.rs` now opens every `tls/` session through this path.

## The program's transport (`AppLinks`)

Before: `AppLinks` had no `begin_initiator`, so the default ran `open_initiator`, whose
`open_link` (`crates/wz-runtime-coop/src/app_link.rs:357`) asked the program for the link and then
waited, with the session held, until the program reported it up: parked on a condition variable for
up to `OPEN_WAIT_MS` (ten seconds, `app_link.rs:69`) on a host, or for a fixed number of turns on an
image. A program that answers `Pending` and reports `connected` from another thread later held
every other caller for as long.

Now `AppLinks::begin_initiator` (`app_link.rs:1122`) claims the buffers, asks the program
(`SessionTransport::begin_open`) and returns a `PendingAppLink` (`app_link.rs:672`) whose `poll`
reads the table's `poll_open` without a waker: `Opening` answers nothing, `Open` makes the
datagram or stream link exactly as `open_initiator` does, `Closed` is a refusal. Dropped while
under way (the engine's deadline, a close), it releases the link and the program is told to close
it. A program that answers `Up` at once is answered at the first poll, so a session over it opens
as before. The open is bounded by the engine's open deadline on the session's clock, which also
replaces `with_open_bound` for a dial; `OPEN_WAIT_MS` and the open bound still apply to a listen
and a group join. Tests: `a_begun_dial_waits_for_no_open_and_is_made_once_the_program_reports_it_up`
and `a_begun_dial_the_program_closes_is_refused_and_one_given_up_is_closed` in `app_link.rs`.

## lwIP

`LwipLinks` (`crates/wz-session-lwip/src/links.rs:182`) dials `udp/` alone: a bind, no wait, and
`tcp/`/`tls/` are refused as unsupported before anything is opened. lwIP's TCP is reached through
`LwipTcpDial` (`crates/wz-session-lwip/src/stream.rs`), whose waiting `dial` (`:245`) loops,
polling lwIP, for up to `DIAL_TIMEOUT_MS` (five seconds). lwIP's connect is itself asynchronous
(`tcp_connect` queues the SYN and a callback sets the state), but lwIP here runs `NO_SYS` and
moves only when polled, so a dial cannot simply return and wait for the callback: someone must
poll. `LwipTcpDial::dial_started` (`:268`) now hands the SYN to lwIP and returns, and
`LwipTcpStream::connected` (`:135`) polls lwIP once per ask and reads the state, so an `IpLinks`
over `LwipTcpDial` dials it like any other `tcp/`. The slot profile's `IpStack` over lwIP (an MCU
node's own loop, not this engine) still uses the waiting dial. Tests:
`a_begun_dial_polls_lwip_once_for_each_ask_and_never_waits` and
`a_begun_dial_to_a_port_nobody_listens_on_is_refused_by_a_later_ask` in `stream.rs`.

## Zephyr `tcp/`: still blocking

`ZephyrIpLinks` (`crates/wz-runtime-zephyr/src/links.rs`, the links of the pico C ABI's Zephyr host,
`crates/wz-capi-pico/src/coop_host.rs:155`) dials `tcp/` with `ZephyrTcpDial`, which has no
`dial_started`: the trait's default runs `ZephyrTcpSocket::connect`
(`crates/wz-runtime-zephyr/src/stream.rs:99`), a blocking `connect` (`:112`) under the session, for
as long as the stack takes to answer or give up the SYN. A `tls/` dial over it (`TlsDial` over
`ZephyrTcpDial`) now steps its handshake, but its connect waits the same way.

Making it non-blocking takes three things this change does not have (Zephyr's sources read at
v4.4.0-6201-gdaad7c59b8e):

1. `O_NONBLOCK` on the socket. Zephyr's `fcntl` is in `subsys/portability/posix/options/fd_mgmt.c`
   (`POSIX_FD_MGMT`), which `POSIX_API` implies but `POSIX_NETWORKING` alone (the
   `deploy/zephyr-app`, `zephyr-tls-loopback`, `zephyr-admin-loopback` images) does not bring, and
   `zephyr-sys` declares neither `fcntl` nor `getsockopt`.
2. Telling a connect under way from one refused at once. A non-blocking `connect` returns -1 for
   both, and the reason is in `errno`, which this crate cannot read through the FFI (its module
   doc says so).
3. Asking a connect under way without a wait that is unsafe. Zephyr's `poll` for `POLLOUT` on a
   native TCP socket waits on the connection's semaphore (`sockets_inet.c`,
   `zsock_poll_prepare_ctx`: `net_tcp_conn_sem_get` while `NET_CONTEXT_CONNECTING`, else
   `net_tcp_tx_sem_get`), and both read `ctx->tcp` without a check (`subsys/net/ip/tcp.c`). Whether
   `ctx->tcp` is always set after a connect that failed at once was not established; reported
   only after `SO_ERROR` (`ZSOCK_SO_ERROR`, 4) is read, which needs `getsockopt`.

Until then a Zephyr image's `tcp/` dial holds the session for the connect; the redial wait is
counted from the end of that connect, so the session is free between dials.

## The trait's default (`Dialled`)

After this change the default `begin_initiator` is used by `LwipLinks`, `ZephyrLinks` and
`MemoryLinks`, whose opens bind a socket or a queue and do not wait, and by `ZephyrIpLinks` for
`tcp/` (above). `IpLinks` itself falls back to `open_initiator` only for `udp/` (a bind) and for a
protocol it does not carry, which is refused before any socket or buffer is taken.
