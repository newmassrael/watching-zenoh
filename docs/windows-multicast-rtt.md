# A multicast round trip that does not finish on Windows

The pico C ABI performance matrix on a Windows 11 x64 host (`scripts/host-bench/windows/perf_matrix.ps1`,
`docs/pico-perf-matrix.md` section 6) lost every repetition of every multicast round-trip cell of
arm W, batching off and on, 8, 64 and 1024 bytes, with `ping did not finish in 274 s`. Arm W's
multicast throughput cells were measured on the same run, and arm P (zenoh-pico) completed its
multicast round trips on the same host. The library measured was the Windows package of commit
3ba877491a (the plan's `package.commit`), on the cooperative engine with `std`.

This note gives the cause, what was changed, every hypothesis that was read and why it was set
aside, and how a Windows run confirms it. Nothing here was built or run: it is a reading of the
code, and section 4 says what a run has to show.

## 1. What the deadline says

The runner gives ping `warmup + ready + pings x 1 ms + (pings / 10 + 1) x timeout + 30 s`: the
time a ping needs when a round trip takes about a millisecond and no more than a tenth of them are
lost. ping gives up by itself (`aborted=1`) once more than a tenth of its pings are lost
(`scripts/host-bench/perf_probe.c`, `run_ping`), and a ping that loses every round trip stops in
about `pings / 10 x timeout` and prints `no round trip came back`. So `did not finish` with the
default 100 ms timeout reads as round trips that do come back, nearly all within 100 ms, but take
some 11 ms or more on average (20000 of them then pass the deadline), or as a ping that hangs. The
first is what the code below produces.

## 2. The cause

In the measured library a put on a group, made by a thread that is not the session's read task,
was pushed onto the group's stage and not written: at 3ba877491a `GroupFace::push`
(`crates/wz-capi-coop/src/engine/group.rs`) is `self.tx.push(item, self)` alone, and the stage is
written by the group's pump, a task of the session that runs only in a read step (`GroupFace::due_us`
there: "pushed onto its stage what its socket has room for, which only a step writes"). A read that
is already waiting on the group's socket is not woken by a push. It waits until the next datagram
arrives or until the bound it worked out before the push: the read's idle wait
(`PICO_SOCKET_TIMEOUT_MS`, pico's `Z_CONFIG_SOCKET_TIMEOUT`) or the group's sweep tick
(`GROUP_TICK_MS`, 50 ms, due while the group holds a member), whichever comes first. On Windows that
wait is a `WSAPoll` timeout, which the system timer ends.

The two sides of the round trip do not meet this alike:

* pong answers from its subscriber's callback, which runs on its read task in `deliver`, after the
  step. The read's next wait is worked out after that, finds the stage holding the answer
  (`due_us` is 0) and does not wait: the next step writes it. pong's leg is fast.
* ping puts from its main thread, which spins on the answer. When the answer is delivered, two
  threads go for the session's lock: the read task, to work out its next wait, and the main thread,
  to push the next ping. If the push comes first, the wait sees the stage and does not wait. If the
  wait comes first, the read task sleeps on the group's socket and the ping lies on the stage until
  the bound: up to 50 ms. Nothing in flight ends the wait sooner but a member's beacon, since the
  datagram that would is the answer to the ping that was not sent.

A round trip is then either fast or up to a tick long, few pass 100 ms, ping does not give up, and
20000 of them at a mean of tens of milliseconds run past 274 s. The group's throughput is not stopped
by it: a publisher that puts back to back fills the stage's lane, and a put that finds the lane full
runs the session's tasks on its own thread (`GroupTxPace::pass`), which write the stage; the cost
shows in the figures only (`docs/coop-engine-cpu-cost.md`, row 1).

Which thread wins the race is the scheduler's, and nothing here measured it. The same code runs on
Linux; a Linux multicast round trip that completes is either a run of a tree that already writes the
put on the putting thread (below), or a host on which the push usually wins. The Windows reading is
consistent with the read task winning often enough to put the mean past 11 ms.

## 3. The fix

The put: `feat(capi-coop): Write a group put on the thread that puts it` (3c80bbe54, in the
integration this branch starts from, not in the measured package). `GroupFace::push` writes what the
push put on the stage, on the caller's thread, before the put returns, through the transport the group's
task shares with its face (`GroupLink::write_staged`, `crates/wz-session-mcu/src/group_drive/stage.rs`),
as zenoh-pico writes a multicast message on its caller's thread
(`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_n_msg_inner(`).
Tests: `tests::group::woken::a_put_on_the_group_is_written_by_the_putting_thread_before_it_returns`,
`tests::group::woken::a_put_made_while_a_read_waits_is_written_by_the_putting_thread`.

The answer: the one way left onto a group's stage from outside the group's step. A member's query
is answered through the group's reply sink (`Core::answer_route`), which only stages; a query the
program keeps and answers or lets go of later, on a thread of its own (`CoopHeld::reply`, its drop),
left its reply and its Final on the stage for the read task's next step, which is the same wait.
`CoopEngine::answer` now writes them on the answering thread (`Core::write_answers`, which calls
`GroupFace::write_staged`), as a put is written. Test:
`tests::group::asked::a_kept_query_answered_by_the_program_is_written_on_the_group_by_its_thread`,
which stops the answering member's read task, so that only the answering thread can write, and finds
the reply and then the Final on the group before each call returns.

## 4. Confirming it on the Windows host

The run, the plan and the host are those of `docs/pico-perf-matrix.md` section 6.

1. The cause, on the package that was measured: one cell with fewer pings, so that ping finishes
   inside the deadline and prints its percentiles.
   `perf_matrix.ps1 -Mode run -Plan C:\wzperf\plan.json -Package C:\wzperf\<the measured zip>
   -Probe C:\wzperf\perf_probe.c -Work C:\wzperf\work -Transports multicast -Workloads rtt
   -Batching off -Sizes 8 -Reps 1 -Pings 1000 -ClientCpus <...> -ServerCpus <...>`.
   Expected: arm W's ping line with `p90_ns` in the millions (milliseconds, up to some 50 ms) and
   `p50_ns` there too when the read task wins the race most of the time, `lost` small, `aborted=0`;
   arm P's ping line, which completes, beside it.
2. The fix: the package of a commit that holds 3c80bbe54 and this branch, its plan made by
   `perf_matrix.py windows-plan` in a checkout of that commit, and the same cell, then the full
   multicast row with the default `-Pings 20000`. Expected: arm W's `p50_ns` below a millisecond
   and every repetition finished.

A ping that still does not finish with the new package is not this cause; `PERF_PROBE_TRACE=1` in the
ping's environment then says whether it stopped in its teardown, and in which call.

## 5. Hypotheses read and set aside

| Hypothesis | What the code says | Verdict |
| --- | --- | --- |
| A receive after an ICMP port unreachable fails with `WSAECONNRESET` and ends the read | Every UDP socket turns the report off at open (`ignore_unreachable_reports`, `SIO_UDP_CONNRESET`, `crates/wz-runtime-posix/src/windows/net.rs`; test `an_unreachable_port_does_not_fail_the_senders_next_receive`). A group's datagrams go to a group, which brings back no port unreachable. And a failed receive ends the group's link (`HostGroupTransport::recv_with` sets `failed`, `carrier_up` turns false, the pump returns `LinkLost`), after which the group is joined again: a loss, not a slow round trip | Not the cause |
| `WSAEMSGSIZE` fails a read | A datagram longer than the buffer is read as the buffer's length (`WindowsUdpSocket::receive`), and a group's buffer is `UDP_RX_CAPACITY` | Not the cause |
| `WSAEWOULDBLOCK` is read as a failure | A receive answers it as nothing yet (`receive`); a send answers it as no room (`found_no_room`), and the stage offers the datagram again | Not the cause |
| `IP_MULTICAST_LOOP` applies to the receiving socket on Windows and to the sending one on POSIX | Under the default `multicast-loopback` (`OsDefault`) no socket is set (`Plan::loop_back`, `crates/wz-runtime-posix/src/multicast.rs`), and every socket's default is on. Under `on` or `off` both of a member's sockets are set, so either system ends with the same delivery. The throughput cells show each member hearing the other on this host | Not the cause |
| Binding the group address is refused on Windows | A link's receiver binds the family's wildcard on the group's port (`RxBind::Wildcard`); only a scouting socket asks for the group address, and on Windows `Plan::rx_bind_addr` binds the wildcard there too | Not the cause |
| `SO_REUSEADDR` against `SO_EXCLUSIVEADDRUSE` | The receiver sets `SO_REUSEADDR` alone (`WindowsUdpSocket::open`), as pico's Windows group listener does (`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_windows.c` @ `SOL_SOCKET, SO_REUSEADDR`); a group's datagram reaches every socket of the host bound to the port and joined | Not the cause |
| A member drops its own looped datagrams by source address, and a Windows source of another interface drops the other member's | wz has no such filter. Its own beacon is dropped by zid (`dispatch_multicast_message`, `join.zid != params.zid`, `crates/wz-session-core/src/multicast_rx.rs`), and its own frames come from a source no beacon admitted, so the sequence-number gate drops them. A member is keyed by the address and port its datagrams come from, its own send socket's, the same for all of them. zenoh-pico's filter is by source (`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_windows.c` @ `if (!((a->sin_port == b->sin_port) && (a->sin_addr.s_addr == b->sin_addr.s_addr))) {`) | Not the cause |
| The Join and the sequence-number judgement | The same code on every host (`multicast_rx`, `MulticastDispatcher`), with nothing from the socket layer but the source; the probe declares its publisher a second after the open and waits for a peer before its first ping | Not the cause |
| A read on Windows is not woken by a datagram | The group's wait is `SocketReadiness` (`WSAPoll` on a `WSADuplicateSocketW` duplicate, `crates/wz-runtime-posix/src/windows/mod.rs`), the wait of the session's `udp/` and `tcp/` links. A wait that never woke would hold both legs of the round trip, pong's too, to the tick. The group tests that read a real datagram run on Unix or are ignored, so no test holds this on Windows | Not the cause of this reading; untested on Windows |
| The group is joined on another interface than the one `#iface=` names | True on Windows: `interfaces::unicast_addresses_of_interface` answers `Undetermined` there, so `#iface={GUID}` is dropped with a warning, the group is joined on the unspecified interface and sent on the system's own choice, where zenoh-pico finds the adapter by its GUID (`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_windows.c` @ `if (_z_str_eq(tmp->AdapterName, iface) == true) {`). Both members then use the same interface, which the throughput cells show carries the group, so it does not explain a loss of round trips alone | Not the cause; a difference from zenoh-pico left open |
