# Windows lane (win-perf): a message's work on the Windows host against zenoh-pico's

Status: design of the Windows performance lane (branch `win-perf-design`). Nothing here was built,
run or measured by this lane. The figures of section 1 are those of the run it names; every other
figure is derived from them or read from the code, and says so. A cell with no reading says
**measure**, and section 7 names the command that fills it. Step S1 of section 5 is on main; S2 is
on the branch `win-s2` (section 6b); S2b needs no code of its own, the engine's read making it
already (section 6b); the rest is design. It extends `docs/coop-engine-cpu-cost.md` (the engine's
own work a message), `docs/windows-multicast-rtt.md` (the group put written by the putting thread) and
`docs/c-abi-migration/base-rss.md` (the resident set on Linux, part by part); it changes none of them.

## 1. The reading

pc3-win (Windows 11 x64), the package `wz-capi-pico-0.1.0-zenoh-pico-preset-windows-x64-nostd-41988298bc`
(zenoh-pico's preset on the cooperative engine, without `std`), against zenoh-pico 1.10.2 built by
`scripts/host-bench/windows/perf_matrix.ps1` as the same build; run `windows-20261127T074002`,
judged by `perf_matrix.py --gate --without-external` against `deploy/pico_perf_ceiling_windows.json`:
84 rows, 26 WIN, 19 TIE, 39 LOSS (`docs/pico-perf-matrix.md` section 6). The `cpu_sys_s_*` and
`cpu_user_s_*` lines of the run's `report.txt` split each process's CPU into the kernel and user
time `GetProcessTimes` gives; the gate judges neither, and they are what sections 2 and 3 read.

| group | rows (W over P) | what the report says |
|---|---|---|
| multicast receive | `multicast/*/thr/*/cpu_ns_per_msg` 1.075 to 1.084, `msgs_per_s` 1.06 to 1.08, `multicast/*/rtt/*/pong_cpu_ns_per_rtt` 1.037 to 1.125 | batching off, the subscriber's CPU a message 9,577, 10,790 and 8,472 ns (8, 64, 1,024 B) against 14,340, 13,840 and 11,500 (1.28 to 1.50); the publisher's 178.6 to 179.8 us against 188.2 to 191.1 us (1.05 to 1.06); pong 181 to 191 us a round trip against 189 to 204 |
| tcp answer and subscriber | `tcp/*/rtt/*/pong_cpu_ns_per_rtt` 1.068 to 1.101, `tcp/off/thr/*/cpu_ns_per_msg` 1.014 to 1.075 | pong 33.0 to 35.5 us against 35.3 to 38.2 (+2.2 to +3.5 us a round trip); the subscriber 7.5 to 8.9 us a message against 8.9 to 10.4 (+0.9 to +2.9), its kernel time 1.13 to 1.50 times P's; the publisher 0.96 to 0.99 and ping 0.996 to 1.063 (batching off) |
| round-trip latency | `rtt_p50_us` 1.017 to 1.038 on multicast and on tcp with batching | +1.3 to +1.9 us at 49 to 52 us on tcp, +4.5 to +9.5 us at 267 to 277 us on multicast |
| resident set | `tcp/*/rss_kib` 1.068 to 1.074 | W 6,136 to 6,352 KiB a process, P 5,740 to 5,960: +376 to +436 a process, on both sides, both workloads and every size |

Not losses: the multicast resident set is a WIN at 0.90 (P's group process holds 6,952 to 7,164 KiB,
W's 6,248 to 6,488); multicast with batching at 8 and 64 B carries 1.24 to 1.45 times P's messages.
The p99 rows are TIE with intervals of 0.4 to 3.0, and `rtt_max_us` reads 2.9 to 4.4 ms for W on tcp
against 0.64 ms for P (section 5, S6).

## 2. Why the receive's instructions on Linux do not show it

The Linux comparison W wins on the receive (Ir 0.757, `docs/win-budget/ir-receive.md`) counts the
instructions the process executes in user mode under callgrind: the kernel's half of a system call is
not among them, nor is a wait. The Windows figures are CPU time, kernel and user, and a Winsock call
costs in both: the user-mode half (`ws2_32.dll`, its provider in `mswsock.dll`, `ntdll.dll`) and the
AFD driver's. A design that makes more calls a message than zenoh-pico's can therefore win Linux's Ir
and lose Windows' CPU, and the losses of section 1 follow the calls of section 3:

- **The multicast subscriber with batching off** is the plainest cell: one datagram a wake (5,100 to
  5,500 a second), no answer. zenoh-pico reads each datagram with one `recvfrom` that waits; W makes
  four calls (section 3.2). The difference, 4.8, 3.0 and 3.0 us a message over three calls, is 1.0
  to 1.6 us a call. Derived from this row alone, assuming the calls are the whole difference; M1
  counts them.
- **The tcp pong** pays +2.2 to +3.5 us a round trip: one or two calls at that price, which is what
  section 3.2 counts (a read that answers `WSAEWOULDBLOCK`, **measure**).
- **The tcp subscriber**'s kernel time is 1.13 to 1.50 times P's while its user time is 0.93 to 1.32.

What is not the cause, by the code: no allocation a message on W (zenoh-pico allocates and frees on
the C runtime's heap; `base-rss.md` section 3), no thread handoff a message (`coop-engine-cpu-cost.md`
section 2), and the same two threads in each process.

## 3. One message, call by call

### 3.1 The primitives

| primitive | wz on Windows | zenoh-pico on Windows |
|---|---|---|
| wait for input | one `WSAPoll` over the session's links (`WindowsWaits::wait_ready`, `poll_on`, `crates/wz-runtime-posix/src/windows/mod.rs:604`) | tcp peer: `select` over the peers (`vendor/zenoh-pico/src/system/windows/network.c` @ `int result = select(0, &read_fds, NULL, NULL, &timeout);`); a group: none, its read is the wait |
| stream read | one `recv` of a non-blocking socket, `WSAEWOULDBLOCK` nothing (`WindowsTcpSocket::try_read`, `crates/wz-runtime-posix/src/windows/stream.rs:395`) | `recv` of a blocking socket after `select` said it has input (`vendor/zenoh-pico/src/link/transport/tcp/tcp_windows.c` @ `int rb = recv(sock._sock._fd, (char *)ptr, (int)len, 0);`) |
| a group's datagram read | the group's sockets are non-blocking (`bind_joined`, `bind_sender`, `crates/wz-runtime-posix/src/multicast.rs:632`, `:674`); a read that must not wait (`WindowsUdpSocket::try_recv`, `crates/wz-runtime-posix/src/windows/net.rs`) was `WSAPoll(0)` and `recvfrom` before S1, `recvfrom` alone after | one `recvfrom` on a blocking socket with `SO_RCVTIMEO`, its own datagrams read and passed over in the same call (`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_windows.c` @ `rb = recvfrom(sock._sock._fd, (char *)ptr, (int)len, 0, (SOCKADDR *)&raddr, (int *)&replen);`) |
| a group's read that waits in its receive | before S2 not on Windows: `MulticastSocket::make_receive_wait` was the provided `false` there (`crates/wz-runtime-posix/src/group.rs:73`), so the split receive did not `awaits_input` (`crates/wz-runtime-posix/src/multicast.rs:1019`), the lone group's read (`read_awaited`, `crates/wz-capi-coop/src/engine/group.rs:2291`) was not taken and the read waited in `WSAPoll`. A POSIX host makes it (`crates/wz-runtime-posix/src/net.rs:1107`) and reads a group with one call a datagram: `read_awaited` steps the datagram the wait kept alone and goes back to the receive, so no read that finds the queue empty follows it (D10 of `docs/win-budget/ir-multicast.md`, section 7.9). After S2 Windows reads the same way: `make_receive_wait` arms `SO_RCVTIMEO` and the first receive that waits turns the joined socket to blocking (section 6b) | the read is the wait |
| stream write | one `WSASend` of the non-blocking socket (`stream.rs:326`); on `WSAEWOULDBLOCK` a `WSAPoll` for room (`poll_writable`, `mod.rs:338`) and again | a blocking `send` (`tcp_windows.c` @ `int wb = send(sock._sock._fd, (const char *)ptr, (int)len, 0);`) |
| datagram write | `sendto` of the non-blocking sender (`WindowsUdpSocket::send_to`); no room is `found_no_room` | a blocking `sendto` |
| clock | `QueryPerformanceCounter`, `QueryPerformanceFrequency` and two 64-bit divisions a reading (`WindowsClock::now_us`, `mod.rs:66`, `windows_arith::ticks_to_us`; `monotonic_ns`, `crates/wz-host-sync/src/windows.rs:75`) | `QueryPerformanceCounter` a reading (`vendor/zenoh-pico/src/system/windows/system.c` @ `z_clock_t z_clock_now(void) {`); `QueryPerformanceFrequency` and a division in each elapsed |
| lock | `RawLock`: one exchange when free; 100 spins, then `WaitOnAddress`, and `WakeByAddressSingle` only from a release that finds it contended (`crates/wz-host-sync/src/lib.rs:153`, `:161`) | `SRWLOCK` (`system.c` @ `AcquireSRWLockExclusive(m);`); a recursive mutex is a `CRITICAL_SECTION` |
| allocation a message | none after the open; the global allocator is the process heap (`process_heap`, `crates/wz-capi-pico/src/os/no_std_host.rs:114`) | `malloc` and `free` of the C runtime, on the same process heap (`docs/win-budget/std-heap.md` section 1.1) |
| threads | the caller and the read task (`CreateThread`, `crates/wz-host-sync/src/windows.rs:98`) | the caller and one executor thread (`system.c` @ `*task = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fun, arg, 0, NULL);`) |
| wake of a waiting read | a loopback datagram socket (`SocketWake`, `net.rs`), made only for a session whose clock the program moves (`time-base`): none in the preset | the executor's condition variable |

### 3.2 The calls a message

From the code; M1 counts them. "Own datagram": a member hears what it sends to the group, since the
loopback that lets the other member of this host hear it is on (on Windows `IP_MULTICAST_LOOP` is the
receiving socket's, and no source filter tells two members of one address apart by port), and both
libraries pass over it in their read.

| side and cell | zenoh-pico | W before S1 | after S1 | after S2 and S2b | after S3 |
|---|---:|---:|---:|---:|---:|
| multicast subscriber, a datagram a wake | 1 (`recvfrom` that waits) | 4 (`WSAPoll`; `WSAPoll(0)`, `recvfrom`; `WSAPoll(0)` that finds it empty) | 3 (`WSAPoll`, `recvfrom`, `recvfrom` answering `WSAEWOULDBLOCK`) | 1 | 1 |
| multicast publisher, a put | 2 (`sendto`; the executor's `recvfrom` of its own datagram) | 5 (`sendto`; the read task's 4 for its own datagram) | 4 | 2 | 2 |
| multicast pong, a round trip | 3 (two `recvfrom`, the ping and its own answer; `sendto`) | 7 to 9 (`sendto`; the two datagrams in one wake or two) | 5 to 7 | 3 | 3 |
| tcp pong, a round trip | 3 (`select`, `recv`, `send`) | 3 or 4 (`WSAPoll`, `recv`, `WSASend`, and a `recv` answering `WSAEWOULDBLOCK` when the turn reads the link again before its next wait: **measure**) | the same | the same | 3 |
| tcp subscriber, a wake | 2 (`select`, `recv`) | 2 or 3, as the pong | the same | the same | 2 |
| tcp publisher, a put | 1 (`send`, which waits for room inside) | 1 (`WSASend`); 3 when the stream is full (`WSAEWOULDBLOCK`, `WSAPoll`, `WSASend`) | the same | the same | the same |

S2b is that `read_awaited`, on main before the package of section 1 was built: on Windows it was
never reached, since no group's receive half waited. S2 alone so moves the multicast rows from the
column after S1 to the column after S2 and S2b. What S2 adds a datagram beside the `recvfrom` is a
`setsockopt` of the receive's timeout whenever the whole milliseconds left of the read's deadline
change (`HostGroupReceive::await_member`, as on Linux): at 5,000 datagrams a second about one in
five datagrams (S2c).

Clock readings a message: W reads the clock at least once in each read step and once in each wait it
works out (`crates/wz-capi-coop/src/engine/direct.rs`, the quiet face's loop; `pump.now_us`), each
reading a `QueryPerformanceCounter`, a `QueryPerformanceFrequency` and two divisions; zenoh-pico reads
it once in each spin of its executor (`vendor/zenoh-pico/src/runtime/executor.c` @
`z_clock_t now = z_clock_now();`). How many W makes is **measure** (M1b).

## 4. The resident set

**The reading.** W's process holds 6,136 to 6,352 KiB on tcp and on udp and 6,248 to 6,488 on
multicast; on tcp that is +376 to +436 KiB over P's, the listener (pong, subscriber) and the dialer
(ping, publisher) alike, at every size and in both workloads. A fixed cost of a process, then, not of a
role, of traffic or of a transport. On Linux, `base-rss.md` section 3 read the library's mappings at
+812 KiB a cell of two processes, about 406 a process: the same size as the whole Windows difference.

| part | wz | zenoh-pico | shared with Linux | Windows only | reading |
|---|---|---|---|---|---|
| the library image | the DLL: about 1.09 MB of read-only sections for the host-peer like-for-like (`arch-win-ext.md` section 2.1); the preset's own **measure** | `zenohpico.dll`, about 0.41 MB (the same table) | `base-rss.md` L1 (the run's code in one place) and L2 (executed code cut) | Windows maps an image page when it is touched and holds no 64 KiB window around it as Linux's page cache does, so the share of the text that is resident is the run's own pages, **measure**; the unwind tables (`.pdata`, `.xdata`) are read only when unwinding | M3 |
| system DLLs | imports `bcrypt.dll` (`BCryptGenRandom`: `WindowsEntropy`, `crates/wz-runtime-posix/src/windows/mod.rs`; getrandom 0.2, `crates/wz-capi-pico-lib/build.rs`) beside `advapi32.dll`, `kernel32.dll`, `ws2_32.dll`, `iphlpapi.dll` and the C runtime's heap API set (`SYSTEM_IMPORTS`, `scripts/lib/pico_windows_package.py`) | `advapi32.dll` for `RtlGenRandom` (`system.c` @ `RtlGenRandom(buf, (unsigned long)len);`), `ws2_32.dll`, `iphlpapi.dll`, `VCRUNTIME140.dll` and the C runtime, which the probe imports in both arms (`/MD`) | | `bcrypt.dll` mapped in W's process alone, unless something else of the process loads it: **measure** | M3 |
| the session arena | reserved and committed at the open (`map_pages`, `crates/wz-host-sync/src/windows.rs:204`); its touched pages | on the heap as it is taken | `base-rss.md` L3 and A1 | none | M3 |
| main stack, `.data` and `.bss`, the read task's stack | as on Linux | | `base-rss.md` L4, L7, the threads row | each thread's stack is committed from the probe's header in both arms | M3 |
| heap | at the open | a message's blocks, freed | `base-rss.md`: W ahead | | |

**What the sides say.** The listener pays what the dialer pays (+376 to +436 against +388 to +412),
where Linux's R0 read the listener's arena at 112 KiB and the dialer's at 48. Either the package holds
A1 (the listener's spare face sets left unwritten), or the arena is not where the difference lies on
Windows: M3 tells.

## 5. The steps, largest first

The estimates price a Winsock call at 1.0 to 1.6 us (section 2) and are derived, not measured. Each
step lands only when its rows fall (M0) and the Linux receive's Ir does not grow
(`docs/win-budget/ir-receive.md`).

| step | what | where | expected | state |
|---|---|---|---|---|
| S1 | A socket made non-blocking is read with no poll before the read: `WSAEWOULDBLOCK` is nothing queued, as the stream seam already reads (`stream.rs:395`). A socket that blocks is still asked first, so a read that must not wait does not | `crates/wz-runtime-posix/src/windows/net.rs` (`try_recv`, `make_nonblocking`), Windows only | one call less for each datagram a group reads, its own included: the multicast subscriber -1.0 to -1.6 us of its +3.0 to +4.8, the publisher the same for its own datagram, pong -2 to -3 us a round trip; multicast `cpu_ns_per_msg` from 1.075 to 1.084 to about 1.06 to 1.07; no tcp row moves | on main |
| S2 | A group's receive waits in its `recvfrom` on Windows too: `make_receive_wait` arms `SO_RCVTIMEO` at the socket's wait and marks the socket as one whose receive waits; `set_receive_timeout` arms the option on such a socket as well; `recv_waiting` of it turns the socket back to blocking at its first call (the mark S1 keeps is cleared then) and is the one `recvfrom` (`WSAETIMEDOUT` is already nothing, `receive`); a read that must not wait polls a socket that blocks first, as before S1. The turn waits for the first receive that waits, so a group read beside other links, which waits in `WSAPoll` and never in its receive, keeps S1's one call. Every socket is opened with `WSA_FLAG_OVERLAPPED` (`open_socket`), which the option needs on a `WSASocketW` socket | `windows/net.rs`, `windows/group.rs` (`MulticastSocket for WindowsUdpSocket`), Windows only | the lone group's read is taken (S2b): per datagram the wait's `WSAPoll` and the read that finds the queue empty go, the subscriber from 3 calls to 1, the publisher's own datagram the same, pong from 5 to 7 to 3; the subscriber's +3.0 to +4.8 us to about 0, the publisher's +9 to +12 us to about +4 to +7, pong to about P's; no tcp row moves | branch `win-s2` |
| S2b | After a datagram a waiting receive took, the lone group's read goes back to that receive and makes no read that does not wait: the read that finds the queue empty goes | `read_awaited`, `crates/wz-capi-coop/src/engine/group.rs:2291`, every host: it steps the datagram the wait kept alone (a step of one, `NonZeroUsize::MIN`) and waits in the receive again | with S2, as there | on main (D10 of `docs/win-budget/ir-multicast.md`); no code: on Windows it is reached once S2 makes the receive half wait |
| S2c | The receive's timeout armed again only when the time left of the read's deadline is shorter than the armed one by more than the host's timer can tell apart, in place of whenever its whole milliseconds change | `HostGroupReceive::await_member` (`crates/wz-runtime-posix/src/multicast.rs`), every host | about one `setsockopt` in five datagrams less at 5,000 a second (section 3.2) | design, after M1 counts it |
| S3 | A short stream read means the stream is drained: the link answers nothing to the next read until a wait reports input, instead of a `recv` that answers `WSAEWOULDBLOCK`. The poll is level-triggered, so what came after the short read ends the next wait at once, and a peer's close is input too | `crates/wz-runtime-coop/src/stream_link.rs` (the receive's read of the part of a batch), every host | if M1 finds that read: -1 call a wake, tcp pong -1.0 to -1.6 us of +2.2 to +3.5, the tcp subscriber the same a wake | design, after M1 |
| S4 | The clock: the frequency read once (it is fixed at boot), and a reading at 10 MHz one multiplication by a constant's reciprocal; one body for `WindowsClock` and `monotonic_ns` | `mod.rs`, `windows_arith.rs`, `crates/wz-host-sync/src/windows.rs` and `counter.rs`, Windows only | a call and two divisions less a reading, some 10 to 30 ns (an estimate); worth a row only at 20 or more readings a message (M1b) | design, after M1b |
| S5 | The putting thread and the read task: a publisher's own datagram is read under the session's hold, and a put that finds it held spins (`live_to_publish`, `coop-engine-cpu-cost.md` row 7); the publisher's +4 to +6 us of user time a put that S1 to S2b do not explain | `crates/wz-capi-coop/src/engine.rs` | **measure** (M2) first | design, after M2 |
| S6 | The longest round trips: W's `rtt_max_us` 2.9 to 4.4 ms on tcp against 0.64; a wait that ended by its timeout, a `WaitOnAddress` sleep or the read task off its CPU | the read task's waits | the p99 rows' intervals | **measure** (M2) first |
| R1 | The resident set's parts on Windows | none: a reading | | M3 |
| R2 | The run's code in one place on Windows: the executed functions given to `lld-link` as `/ORDER:@file` (the DLL is linked by `rust-lld` as `lld-link`, `crates/.cargo/capi-nostd.toml`), Windows' form of `base-rss.md` L1 | the DLL's link | from the touched pages of the whole text to those of the run's span, at most the whole of the +376 to +436 (**measure**, M3) | design, after M3 |
| R3 | No `bcrypt.dll`: the entropy source over `ProcessPrng` or over `RtlGenRandom` (`SystemFunction036`, which the DLL already imports), and getrandom 0.2's import of `bcrypt` out of the Windows graph | `WindowsEntropy`, the graph of `wz-capi-pico-lib` | the module's resident pages, if M3 finds it in W's process alone | design, after M3 |
| R4 | `base-rss.md` L3, L4 and L7 as written | | as there | there |

**S1 alone.** It is the step no measurement needs: a non-blocking socket answers `WSAEWOULDBLOCK`
when nothing is queued, which `receive` already reads as nothing, so the poll before it said nothing
the read does not. It removes about a third of the gap the multicast rows show and none of the tcp
gap; S2 carries the rest of the multicast rows (with S2b, already there), S3 the tcp ones.

## 6. S1, and why Linux does not see it

- **Windows only.** `crates/wz-runtime-posix/src/windows/net.rs` is compiled under
  `#[cfg(windows)] pub mod windows;` (`crates/wz-runtime-posix/src/lib.rs:203`): a Linux build, its
  receive's Ir and its size are what they were. The POSIX `PosixUdpSocket::try_recv` already reads
  with `MSG_DONTWAIT`, one call (`crates/wz-runtime-posix/src/net.rs`).
- **What it changes.** `WindowsUdpSocket` keeps whether `make_nonblocking` made it so; `try_recv`
  polls only a socket that blocks. The sockets `make_nonblocking` is asked of are a group's
  receiver and sender and a scouting socket (`multicast.rs`); a unicast `udp/` link's socket blocks
  and is read as before.
- **Tests** (`windows/net.rs`, run on a Windows host): `a_socket_made_non_blocking_is_read_with_no_poll_before_it`
  (counts the polls of the thread, as the stream seam's `a_read_asks_the_stream_with_no_poll_before_it`
  does) and `a_blocking_socket_is_asked_before_a_read_that_must_not_wait`.

## 6b. S2, and why Linux does not see it

- **Windows only.** The files S2 changes are `crates/wz-runtime-posix/src/windows/net.rs`,
  `windows/group.rs` and the module text of `windows/mod.rs`, all under
  `#[cfg(windows)] pub mod windows;` (`crates/wz-runtime-posix/src/lib.rs:203`). No file a Linux
  build compiles changed: the bytes of every case of `scripts/lib/size_ledger_gate.py`
  (`pico-client-coop-nostd`, `pico-peer-coop`, `pico-api-coop-nostd`) and the receive's Ir
  (W over P 0.757, `docs/win-budget/ir-receive.md`) are what they were. The shared code S2 lets
  Windows reach (`HostGroupTransport::split_receive`, `HostGroupReceive::await_member`,
  `read_awaited`) is unchanged.
- **Why the turn to blocking waits for a receive that waits.** Winsock has no flag that keeps one
  read from waiting (`MSG_DONTWAIT`), so a socket reads at once in one call or waits in one call,
  never both. The engine waits in a group's receive only where the group is the one input of the
  read (`link_wait`, `GroupPump::awaits`); a session with a link beside its group waits in
  `WSAPoll` and reads the group with reads that must not wait, which a non-blocking socket makes in
  one call each. Turning the socket at the split, as a POSIX host does, would give that session a
  poll before each read.
- **What it costs.** On Windows the DLL's text grows by the option's arm and the turn: an estimate
  of 0.1 to 0.3 KB, **measure** on the package's release DLL (`pico_windows_package.py
  --size-judge` over what `size_ceiling.ps1` leaves). A joined socket turned blocking stays so: a
  session whose group read waited in its receive and that later reads beside a link polls before
  each read of the group, one call more a datagram, as before S1. Winsock leaves a socket's state indeterminate after a receive timed out and names the
  loss of data for TCP; zenoh-pico reads its Windows group socket under the same option on every
  receive (`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_windows.c` @
  `SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)`), and the tests below read a datagram on a
  socket whose receive timed out before.
- **Tests** (run on a Windows host with `host-multicast`), each with the line that turns it red:
  `windows/net.rs` `a_receive_made_to_wait_is_one_recvfrom_bounded_by_its_timeout` (a
  `recv_waiting` that polls, or that reads the socket while it still returns at once: the
  `waits_in_receive()` test of `recv_waiting`; a `set_receive_timeout` that leaves the option
  unarmed), `a_read_that_must_not_wait_asks_a_socket_turned_blocking_first` (the
  `self.nonblocking.store(false, ..)` of `waits_in_receive`),
  `a_receive_not_made_to_wait_waits_in_a_poll` (the `receive_waits` test of
  `set_receive_timeout` and of `waits_in_receive`); `windows/group.rs`
  `a_groups_receive_half_waits_in_its_receive_past_its_own_datagrams` (the override of
  `make_receive_wait` in `MulticastSocket for WindowsUdpSocket`).

## 7. Measurements for the main session

The plan, the package and the host are `docs/pico-perf-matrix.md` section 6's; `<run-args>` below is
`-Plan C:\wzperf\plan.json -Package C:\wzperf\<the zip> -Probe C:\wzperf\perf_probe.c -Work C:\wzperf\work
-ClientCpus <...> -ServerCpus <...>` with the pinning `-Mode idle-cpus` prints.

**M0, the rows.** The package of a commit that holds S1, its plan made by `perf_matrix.py windows-plan`
in a checkout of that commit, the full matrix (`-Mode all`), then the gate. For a quick look first:

```sh
ssh pc3-win "powershell -NoProfile -ExecutionPolicy Bypass -File C:\wzperf\perf_matrix.ps1 -Mode all <run-args> -Transports multicast -Reps 3 > C:\wzperf\run-mc.log 2>&1"
```

Expected after S1: the multicast subscriber's `cpu_ns_per_msg_sub` with batching off down by 1.0 to
1.6 us a message, `multicast/*/thr/*/cpu_ns_per_msg` near 1.06 to 1.07; tcp unchanged.

**M0 for S2.** First the build of the branch, from `crates/` on Linux, each command one crate and
one target (the Windows standard library of the pinned toolchain installed with
`rustup target add x86_64-pc-windows-msvc`):

```sh
cargo clippy -p wz-runtime-posix --target x86_64-pc-windows-msvc --lib --tests --features host-multicast -- -D warnings
cargo clippy -p wz-runtime-posix --target x86_64-pc-windows-msvc --lib --tests -- -D warnings
cargo clippy -p wz-runtime-posix --target x86_64-pc-windows-msvc --lib --no-default-features --features session-slot -- -D warnings
```

Then the unit tests on the Windows host, in a checkout of the branch there (`windows/net.rs` and
`windows/group.rs` of section 6b among them; without `host-multicast` none of the four is built):

```sh
ssh pc3-win "cd <checkout>\crates && cargo test -p wz-runtime-posix --lib --features host-multicast windows::"
```

Then the multicast cells, with the preset package of the commit that holds S2 and its plan made as
`docs/pico-perf-matrix.md` section 6 makes them (`-PicoSource` beside `<run-args>`, which
`-Mode all` builds arm P from):

```sh
ssh pc3-win "powershell -NoProfile -ExecutionPolicy Bypass -File C:\wzperf\perf_matrix.ps1 -Mode all -PicoSource C:\wzperf\zenoh-pico.zip <run-args> -Transports multicast -Reps 3 > C:\wzperf\run-mc-s2.log 2>&1"
```

Expected after S2: the multicast subscriber's `cpu_ns_per_msg_sub` with batching off down by a
further 2.0 to 3.2 us a message (the wait's `WSAPoll` and the read that finds the queue empty),
`multicast/*/thr/*/cpu_ns_per_msg` near or under 1.0, pong's `pong_cpu_ns_per_rtt` down by 2 to 4
calls' worth; tcp unchanged. M1 on the same cell counts one `recvfrom` a datagram on the
subscriber and no `WSAPoll` a datagram, and the `setsockopt` S2c is about.

**M1, the calls a message.** Winsock's driver logs each operation to the
`Microsoft-Windows-Winsock-AFD` provider; `logman` and `tracerpt` are in every Windows. One cell of
each kind, a few seconds, traced (the trace slows the cell: it counts, it does not time):

```sh
ssh pc3-win "logman start wzafd -p Microsoft-Windows-Winsock-AFD 0xFFFFFFFFFFFFFFFF 5 -o C:\wzperf\afd.etl -ets"
ssh pc3-win "powershell -NoProfile -ExecutionPolicy Bypass -File C:\wzperf\perf_matrix.ps1 -Mode run <run-args> -Transports multicast -Workloads thr -Batching off -Sizes 8 -Reps 1"
ssh pc3-win "logman stop wzafd -ets"
ssh pc3-win "tracerpt C:\wzperf\afd.etl -o C:\wzperf\afd.csv -of CSV -y"
```

Count the events of each process by event name and divide by what the cell's lines say it did
(`received=`, `sent=`, `answered=`); the run's `cells.jsonl` and the probes' outputs name each
side. Then the same with `-Transports tcp -Workloads rtt` and `-Workloads thr`. The cells of section 3.2
marked **measure** are the tcp rows' fourth call. Where the provider is not enough, the kernel's own
system call events: `xperf -on PROC_THREAD+LOADER+SYSCALL`, the cell, `xperf -d C:\wzperf\sys.etl`
(the Windows Performance Toolkit; `where xperf` says whether the host has it).

**M1b, the clock readings a message.** On Linux, where the same engine reads `PosixClock::now_us`,
which is out of line for this reason: the receive's callgrind run of `docs/win-budget/ir-receive.md`,
its call count of `wz_runtime_posix::PosixClock::now_us` over the messages of the run.

**M2, the threads.** `wpr -start CPU -filemode`, one tcp round-trip cell and one multicast throughput
cell, `wpr -stop C:\wzperf\cpu.etl`; in Windows Performance Analyzer, CPU Usage (Precise) by process
and thread: each thread's CPU, its context switches and what readied it. It says whose CPU S5 is
(the publisher's main thread or its read task), and whether S6's long round trips are waits that ended
by a timeout.

**M3, the resident set's parts.** A pair of probes by hand with a long window, the module list of
each, and the working set of each image from Sysinternals VMMap where the host has it. A script on the
host, `C:\wzperf\m3.ps1`, run once for each arm (`powershell -NoProfile -ExecutionPolicy Bypass -File
C:\wzperf\m3.ps1 -Arm W`, then `-Arm P`):

```powershell
param([string]$Arm = 'W', [int]$Port = 27447)
$exe = "C:\wzperf\work\bin\perf_probe_$Arm.exe"
$subArgs = @('sub', '-m', 'peer', '-l', "tcp/127.0.0.1:$Port", '-w', '1000', '-t', '60')
$pubArgs = @('pub', '-m', 'peer', '-e', "tcp/127.0.0.1:$Port", '-M', '-s', '8', '-t', '60')
$sub = Start-Process -PassThru -NoNewWindow $exe -ArgumentList $subArgs -RedirectStandardOutput "C:\wzperf\m3-$Arm-sub.txt"
Start-Sleep -Seconds 2
$pub = Start-Process -PassThru -NoNewWindow $exe -ArgumentList $pubArgs -RedirectStandardOutput "C:\wzperf\m3-$Arm-pub.txt"
Start-Sleep -Seconds 20
foreach ($p in $sub, $pub) {
    tasklist /m /fi "PID eq $($p.Id)"
    if (Get-Command vmmap64.exe -ErrorAction SilentlyContinue) {
        vmmap64.exe -accepteula -p $p.Id "C:\wzperf\m3-$Arm-$($p.Id).csv"
    }
}
Stop-Process -Id $pub.Id, $sub.Id
```

The rows to read: the private working set (the arena, the heap, the stacks), the working set of
`wz_capi_pico.dll` against `zenohpico.dll` (R2), and whether `bcrypt.dll` is in W's list and not in
P's (R3). VMMap's command line is Sysinternals' own; where the host has no VMMap, the module lists and
the probes' peak working set lines are the reading.
