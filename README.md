# XTun

XTun is an experimental encrypted IPv4 tunnel built on xnet2lua. Packet
processing is implemented in C, with plain-text CFG configuration. Windows
uses Wintun and Linux uses TUN. XTun uses its own protocol over DTLS; it does
not interoperate with WireGuard.

## Current scope

- Windows 10/11 x64 and Linux x64, one tunnel and one peer per process.
- Explicit IPv4 split routes by default, with opt-in IPv4 full tunneling
  and optional per-adapter DNS on Windows clients.
- DTLS 1.2 restricted to ECDHE-PSK with ChaCha20-Poly1305 and X25519.
- A unique, random 32-byte PSK and an expected identity for each peer.
- Automatically negotiated inner MTU, authenticated parameter exchange, bounded receive and
  transmit queues, IPv4 checksum/length and source/destination authorization.
- Normal-exit cleanup, idle detection, full-handshake session renewal.
- A no-adapter `--probe` mode for testing the actual secure UDP transport.
- Optional bounded, unordered DATA recovery using batched NACKs (`arq=1`).

The initial command-line version requires administrator/root access to create
adapters and routes. Service installation, automatic crash recovery, IPv6,
multiple peers and seamless endpoint migration are not implemented.
The UDP address API currently accepts numeric IPv4 addresses only.

## Build

```sh
git clone --recursive https://github.com/1dao/xtun.git
cd xtun
make -j8
make test
```

On Windows use MinGW-w64 GCC and `mingw32-make`. On Linux use GCC and GNU Make.
The CFG reader and mbedTLS are compiled from `core/`; no Lua runtime or
system TLS library is needed. The output is `bin/xtun.exe` or `bin/xtun`.
The DTLS wrapper is owned by XTun in `src/xdtls.c` and `src/xdtls.h`;
`core/` supplies the unchanged xnet2lua networking and third-party libraries.
`XNET_ROOT=/path/to/xnet2lua` can select a different core checkout.
Windows and Linux object directories are separate, allowing WSL and Windows
builds in the same checkout.

For Windows, put the official, signed x64 `wintun.dll` beside `xtun.exe`.
Obtain it from [Wintun](https://www.wintun.net/) and retain its distribution
license. The driver binary is not committed to this repository. XTun loads
only the DLL adjacent to its executable, not one from the working directory.
`pwsh -File tools/get_wintun.ps1` downloads version 0.14.1, checks the pinned
archive SHA-256 and Windows signature, and copies the x64 DLL and license.
It does not install a driver or create an adapter.

## Windows desktop client

The optional desktop client is written in C with raylib and raygui. Build it
with MinGW-w64 and a Windows x64 static raylib library:

```powershell
mingw32-make gui RAYLIB_ROOT=C:/source/ops/raylib RAYGUI_ROOT=C:/source/ops/raygui
```

The default dependency paths point to sibling checkouts under `../../ops`.
`RAYLIB_STATIC` can override the library path. Keep `xtun-gui.exe`,
`xtun.exe`, `wintun.dll` and the third-party notices together when distributing
the build. The GUI needs no Lua script or raygui DLL at runtime.

From the directory where you keep `client.cfg`, launch `xtun-gui.exe` as
administrator. For example, run this from the project root in PowerShell:

```powershell
Start-Process .\bin\xtun-gui.exe -Verb RunAs -WorkingDirectory (Get-Location).Path
```

Use **+** beside the profile list to add a tagged connection to that
`client.cfg`. The first save creates the file if needed. Removing a
connection deletes its tagged fields. A top-level shared `psk` remains in the CFG.

Select a profile to view its routing mode and tunnel addresses. Only one
profile runs at a time. When switching profiles, the current client exits
before the next starts. Disconnecting or closing the window asks the client
to exit normally so it can remove its network resources. Expand the log
panel to see or copy recent client messages.

## Configure and run

XTun always reads configuration from the current working directory. The
server reads `server.cfg`; the CLI and GUI clients read `client.cfg`.
The project root includes a starter `server.cfg` on UDP port 52230. To
try the example pair instead, use the examples directory as the working
directory on both sides:

```sh
cd examples
../bin/xtun keygen
# Paste the same generated value into psk= in client.cfg and server.cfg.
../bin/xtun client --check
../bin/xtun server --check
```

Set `psk` to the same random 32-byte key, encoded as 64 hexadecimal
characters, on both ends. `xtun keygen` prints a fresh key. In a tagged
client CFG, `work.psk` overrides the top-level `psk` for the work tag.
Use separate keys for different clients. Restrict access to CFG files that
contain keys (for example, `chmod 600 server.cfg` on Linux), and keep their
real values out of Git. The repository templates intentionally leave
`psk=` empty.

Edit `examples/client.cfg` to set the server's reachable IPv4 address. The
example addresses are documentation/test networks. Configure the matching
addresses, identity and key on both hosts. Use one unquoted `key=value` per line, with `#` for comments and commas
between CIDRs. XTun uses the core CFG reader, which also checks same-name
environment variables for settings omitted from the file. Convert existing
Lua tables to CFG before starting the new binary.

A client CFG can contain several connections. List the tags in order as
`tags=work,personal` and prefix each connection's fields with its tag
and a dot, for example `work.endpoint=192.0.2.2`. A tag is case-sensitive
and contains up to 31 ASCII letters, digits, underscores or hyphens,
with no leading hyphen. An optional `work.label` is the name shown in the
GUI. Save Unicode labels as UTF-8 without a BOM.

Save the tagged configuration as `client.cfg` in your working directory:

```sh
../bin/xtun client --tag work --check
../bin/xtun client --tag work
```

When the file lists multiple tags, choose one with `--tag`. A file with one
tag uses that tag by default. An untagged client CFG is still supported by
the CLI. Server CFG files remain untagged.

Start the server first, then the client, from an elevated/root terminal:

```sh
../bin/xtun server
../bin/xtun client
```

After `READY`, ping the peer tunnel IP. In split mode, only configured routes
are installed. Ctrl+C performs cleanup.

- `routes`: networks reachable through the peer, also authorized remote packet
  sources. The peer tunnel address is automatically included as a /32.
- `local_networks`: server-only authorization for additional networks behind
  the server. It does **not** install routes, enable kernel forwarding, or
  configure NAT. The local tunnel address is automatically included.
- `name`: an unused interface name, at most 15 ASCII letters/digits/`_`/`-`.
- `bind`, `bind_port`: outer UDP bind address/port. A server defaults to `port`;
  a client defaults to an ephemeral port.
- `session_seconds`: full-handshake renewal interval, 30..86400, default 3600.
- `run_seconds`: optional bounded runtime, default 0 (until interrupted).
- `mtu`: inner MTU ceiling, `0` (automatic, default) or `1280..1400`.
  For a tagged client use `work.mtu=0` with the actual tag. After DTLS
  handshaking, each end subtracts the 8-byte tunnel header (and reserves another
  2 bytes if offering ARQ) from its actual
  maximum DTLS payload and applies this ceiling. Both ends confirm the smaller
  offer before enabling data and updating their adapters. `MTU_OFFER` and
  `READY` log the calculation and selected value. Use `mtu=1280` to retain the
  previous inner packet size. This is capacity negotiation, not path MTU discovery.
- `arq`: `0` (default) or `1`. Both updated peers must set `arq=1` to enable
  recovery; tagged clients use e.g. `work.arq=1`. With only one updated peer
  opting in, negotiation falls back to ordinary DATA. An older binary that
  does not recognize the ARQ capability must be upgraded before opting in.
  No change is needed in `core`. Start with `mtu=1280` when comparing performance.
- `arq_log`: `0` (default) or `1`. Enable on both ends for short diagnostics;
  tagged clients use e.g. `work.arq_log=1`. This is independent of `stats_interval`.
  `ARQ_EVENT` lines include wall-clock seconds, monotonic milliseconds, direction
  and a local session identifier. Events trace gap detection/filling/expiry,
  timer start/expiry/rearm/cancellation, NACK send/receive, queued/sent/skipped
  repairs, watermark exchange and session clearing. `gap_detect` reports the
  missing range; NACK previews show at most 16 sequence numbers with an omitted
  count. `repair_skip` explains cooldown, retry limits, budget and cache misses.
  No keys or packet contents are logged. Logging can affect timing, so disable
  it for throughput comparisons. A `gap_filled` event may still be a late original;
  correlate sequence numbers with the sender's `repair_sent` events when debugging.
- `stats_interval`: seconds between `LIVE_STATS` lines (0 disables, default).
  Set to 1 on both ends for diagnostics; for a tagged client use
  `work.stats_interval=1` with the actual tag. Counters are cumulative.
  `unix` is the wall-clock timestamp and `elapsed_ms` is monotonic elapsed
  time. `udp_tx`/`udp_rx` count outer UDP datagrams; `tun_tx_bytes` is
  written to the adapter and `tun_rx_bytes` is read from it and sent.
  `win_oversize` counts Windows adapter read drops, and
  `win_ring_full`/`win_write_err` split injection failures. A full adapter
  read queue leaves the backlog in the Wintun ring instead of dropping it.
  `ARQ_STATS` reports feedback packets, requested sequence numbers, actual
  retransmissions, duplicates, expiry, cache misses and budget suppression.
  `gap_filled` means arrival after requesting a missing packet; a late original
  can also fill that gap, so it does not by itself prove a retransmission helped.

On Linux, optional server settings `PostUp` and `PostDown` run trusted shell
commands with the server's privileges. `PostUp` runs after the TUN interface
is configured and before the session loop. A failed `PostUp` aborts startup
and attempts `PostDown`. On normal shutdown, `PostDown` runs before adapter
removal. Use cleanup commands that can handle partial setup. `--check` and
`--probe` do not run hooks. A forced kill cannot run cleanup.

Use the commented, scoped iptables example in the root `server.cfg` or
your own firewall rules. The example is idempotent: `PostUp` checks before
adding and `PostDown` removes every copy, so restarts do not accumulate
duplicate rules. Hooks run through `/bin/sh`, and `PostUp` enables
shell error checking. `PostDown` reports its shell exit status, so a cleanup
script that tries several operations should return failure if any fail.
IPv4 forwarding is still a system setting. The Linux integration test
demonstrates these operations inside isolated network namespaces.

For IPv4 full tunneling, set `full_tunnel=true` on the Windows client and
omit `routes`. Keep `bind` unset or set to `0.0.0.0`. On the Linux server
set `local_networks=0.0.0.0/0` to authorize forwarding to arbitrary
IPv4 destinations and receiving their replies. Configure Linux IP forwarding
and NAT (or return routing) separately. The server still authorizes the
client's tunnel source address through `routes` and the automatic peer /32.

After peer authentication, the client preserves an IPv4 /32 route for the
server endpoint on its original interface, then installs two /1 routes on
Wintun. Existing more-specific routes, including local subnets, can still
take precedence. Optional `dns=1.1.1.1` sets one IPv4 DNS server on
the Wintun adapter (Windows 10 build 19041 or later). Choose a DNS address
routed through Wintun. The adapter and its DNS settings are removed on normal
exit, and startup failures roll back routes created by XTun. IPv6 and
DNS policy on other interfaces are outside this mode; it does not enforce
exclusive DNS or provide a kill switch. Restart after changing uplinks.

## Test

`make test` covers real UDP loopback, forced-suite DTLS interoperability,
handshake loss/timeouts, wrong keys/identities, replay/tampering, reordering,
send backpressure, receive bounds, IPv4 validation and address authorization.
It also runs ARQ tests through real DTLS records: feedback/repair loss,
exponential timers, expiry, deduplication, and 70,000 messages across 16-bit rollover.
`python3 tests/config_test.py` checks CLI and configuration rejection paths
without modifying the network.
`python3 tests/mtu_test.py` checks automatic/unequal MTU ceilings and READY
retries under deliberate packet loss over loopback UDP, without adapters/routes.

On Linux as root, with `iproute2`, `nftables`, `ping` and Python 3 installed:

```sh
python3 tests/integration_linux.py
# Optional: real TUN forwarding with ARQ and bidirectional injected 3% loss.
XTUN_TEST_ARQ=1 python3 tests/integration_linux.py
# Also validate gap/timer event logs under injected loss.
XTUN_TEST_ARQ=1 XTUN_TEST_ARQ_LOG=1 python3 tests/integration_linux.py
```

It creates three temporary network namespaces, tests TUN ICMP, forwarding,
NAT, IPv4 fragmentation, a 2 MiB TCP SHA-256 transfer, UDP echo and session
renewal, then verifies adapter/route cleanup. Host routes and firewall policy
remain unchanged. This test is not a throughput benchmark.

On Windows with an Arch Linux WSL distribution already built:

```powershell
pwsh -File tests/probe_windows.ps1
```

This tests Windows-to-Linux secure UDP without creating a Windows adapter.
It is separate from a real, elevated Wintun acceptance test.

For a sustained test after the real tunnel is running, `tests/soak.py` provides
a Linux transfer service and a Windows client monitor. Use a dedicated test
directory on each host:

```sh
python3 tests/soak.py serve --work /path/to/test-directory --pid SERVER_XTUN_PID
```

```powershell
python tests/soak.py client --attach-pid CLIENT_XTUN_PID --work build/soak --seconds 1800
```

The service binds only the tunnel address (default `10.77.0.1`), using TCP 9001
and UDP 9002. It repeatedly transfers 64 MiB files in both directions and
checks SHA-256 after each complete file. Independent 1000-byte UDP echo probes
measure round-trip delay and five-second non-return counts. CPU and RSS are
sampled every five seconds; CPU percentages use one logical CPU = 100%.
Results are written as JSON/JSONL in the client test directory. A partial file
at the time limit is not counted as a complete, verified transfer.
UDP event logs separate send/receive errors, five-second timeouts, late echoes,
duplicates and unknown IDs. `integrity_passed` reports file correctness;
`status=completed` does not assert an acceptable UDP loss or throughput level.
Record concurrent traffic (for example SSH proxy video playback) separately;
shared-link results are not an isolated tunnel bandwidth benchmark.
On exit, `STATS` separates DTLS input overflow, transmit queue, peer/frame/IP
validation, adapter write and device drops. `UDP_STATS` reports socket-level
oversize/errors and send backpressure separately; neither includes kernel or
WAN drops that occur before the application receives a datagram.

Attach mode leaves the existing client running. The operator must stop that
client normally, stop the server/test services, and remove test data and
temporary network resources after collecting results. UDP non-return includes
either direction and application queues; it is not one-way WAN packet loss.

## Protocol and operational limits

DTLS authenticates and encrypts the complete application message. Its record
sequence numbers, nonce construction, replay window and handshake retransmits
are managed by mbedTLS. There is no custom encryption. DATA recovery is disabled
by default and remains best effort when enabled. Inner TCP retains its own
reliable delivery; ARQ does not guarantee prevention of TCP congestion responses.

Each application message has an 8-byte header: version (u8, currently 1), type
(u8), reserved flags (u16, zero), payload length (u32, big endian). Types are
READY=1, DATA=2, PING=3, PONG=4 and CLOSE=5. DATA contains exactly one IPv4
packet. READY carries the sender and expected peer IPv4 addresses (u32 each,
network order), local MTU offer (u16), confirmed MTU (u16, initially zero),
MTU negotiation version (u8, currently 1), ARQ offer (u8, 0/1), ARQ confirmation
(u8, 0/1), and one zero byte: 16 bytes total. ARQ is selected only if both offer it.
The confirmed MTU must equal the smaller of the two offers. DATA is enabled
only after receiving the peer's confirmation; READY is retried until then.
Both ends must be updated: the older 12-byte READY format is rejected.
PING/PONG carry eight
opaque bytes; CLOSE has no payload. Control messages and unknown versions
never reach the virtual adapter.

When ARQ is enabled, ARQ_DATA=6 contains a big-endian 16-bit sequence followed
by one IPv4 packet; ARQ_NACK=7 contains up to 512 missing 16-bit sequences;
ARQ_MARK=8 contains only the last successfully sent DATA sequence (16 bits).
Each direction starts at 1, wraps through zero, and keeps its own sequence space.
Repairs reuse the original application sequence but are encrypted into a fresh
DTLS record. There are no positive ACKs and no global in-order delivery queue.

The receiver gives each new gap a 5 ms reordering grace period before its first
NACK. Each missing sequence then independently backs off through 20, 40, 80
and at most 160 ms between requests, measured from successful feedback writes.
Only due sequences are batched, with at least 5 ms between feedback packets.
A single timer tracks the earliest per-gap deadline, so new gaps do not inherit
an older gap's long backoff. The gap-free path does not scan the receive window.
An empty missing set cancels the timer. Queued feedback is refreshed before
encryption without bypassing a newer gap's grace period; an outstanding DTLS write
is always retried unchanged. Each sender advertises its watermark every 200 ms
while it has sent DATA within the last second, repeating unchanged watermarks
to expose tail loss; idle connections stop advertising after that period.

Recovery uses a fixed 1024-packet cache/window and a one-second eligibility
limit, whichever is exhausted first. Only successfully sent originals enter
the cache. Each packet can be repaired up to three times. The cooldown between
successful repairs uses 1.5 times the larger of the latest and smoothed PONG RTT,
clamped to 20–500 ms; it defaults to 100 ms before an RTT sample is available.
The first PING is queued immediately after session activation. With ARQ enabled,
PING samples RTT every second while either direction has carried payload data
within the last five seconds; idle tunnels retain the 20-second keepalive interval.
Control traffic does not extend the active sampling period.
Repairs overtake unsent DATA while preserving original and repair FIFO order;
an outstanding DTLS write is always completed unchanged. Requests blocked by
the local byte budget or queue are retained and retried when resources permit,
within the same cache/window and expiry limits. Repair messages have a plaintext byte budget of 25% of
original message bytes plus an initial allowance of four maximum MTUs. Earned
credit can accumulate up to 128 maximum MTUs to absorb short loss bursts;
this does not change the 25% earning rate. Control and DTLS/UDP/IP
overhead are additional. Memory per enabled peer is bounded at roughly 1.5 MiB.
`ARQ_STATS` reports deferred repair wait counts in disjoint millisecond ranges
0–10, 11–50, 51–100, 101–250, 251–500 and over 500, plus `defer_wait_sum_ms`.
These cumulative counts cover deferred requests that successfully entered the
send queue and sum to `deferred_queued`; divide the wait sum by that count for
the mean. They exclude requests abandoned while waiting, which are counted by
`deferred_expired`, and exclude time spent in the send queue or network.
Out-of-window/ambiguous jumps cause a session reset; 16-bit serial comparison
still requires an active sequence span below half the sequence space and cannot
provide arbitrary-blackout reliability. Sequence/feedback state is cleared on
session renewal. This is optional loss recovery, not a replacement for congestion
control, path MTU discovery or application reliability. Enable only for measured
comparisons; better video playback on a particular path is not yet established.

The single server slot and its input queue are bounded. A candidate handshake
is pinned to one source tuple for at most 15 seconds; DTLS cookies validate
that tuple. This is not a hardened multi-client Internet-facing dispatcher:
unauthenticated traffic can still contend for the single slot. A live session
does not accept a changed source tuple. Reconnection uses a fresh handshake.

Sessions renew after their configured lifetime or 2^24 sent application
records; idle sessions expire after 60 seconds. Renewal has a brief packet
loss window rather than seamless overlapping sessions. Default session
resumption and renegotiation are disabled. Secrets are cleared on teardown.

Adapter MTU starts at 1280 and changes to the confirmed value before data is
enabled. Session resets restore 1280 and the next handshake negotiates again.
Buffers have a separate fixed 1400-byte inner-packet bound. The OS handles
normal IPv4 fragmentation/DF/ICMP behavior; packets exceeding the negotiated
inner MTU are dropped and counted. The DTLS datagram budget remains 1400 bytes
(excluding outer UDP/IP headers). This does not probe the network path or
guarantee fragmentation-free delivery. Smaller-path support, probe-based MTU
increases and automatic fallback require a future path MTU implementation.

Normal cleanup removes only resources created by the process. Forced process
termination and host crashes are outside the initial recovery guarantee.
This implementation and tests do not constitute a security audit.
