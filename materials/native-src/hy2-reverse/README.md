# NativeRouting HY2 reverse worker

`nr-hy2-reverse` provides device-scoped TCP and UDP port forwarding between two
NativeRouting routers. It is a small, standard-library-only Go program. The
client initiates **every control and work connection through an explicitly
configured local SOCKS5 listener**; that listener is pinned by the firmware to
the existing Hysteria 2 outbound. There is no direct transport fallback.

This worker does not implement Hysteria, TLS, or a new encryption scheme. Its
internal control endpoint must only be reachable through the firmware's
device-specific HY2 ingress, using the additional independent device token.
**Never expose its plaintext control endpoint on the public Internet.** Public
service mappings and the private control endpoint are separate listeners.

## Build and commands

Build with Go 1.26.4:

```sh
python3 materials/native-src/hy2-reverse/build.py --go /path/to/go1.26.4/bin/go
```

The result is a static Linux/amd64 executable. The recipe sets `CGO_ENABLED=0`,
uses `-trimpath -buildvcs=false -ldflags='-s -w -buildid='`, and has no downloaded
Go dependencies. The root material and source manifests must be updated after
rebuilding the runtime binary.

```sh
nr-hy2-reverse check -config /private/config.json
nr-hy2-reverse check-ports -config /private/config.json
nr-hy2-reverse run -config /private/config.json
nr-hy2-reverse version
```

`check` validates configuration without touching network or status files.
`check-ports` additionally checks server TCP/UDP listeners, including IPv6
wildcards. The trusted lifecycle may pass `-exclude-pid PID` **only after
verifying the existing worker's executable and process-start identity**. It
matches that process's socket inodes against `/proc/net/{tcp,tcp6,udp,udp6}`;
unrelated owners remain conflicts. It briefly binds free public mapping ports.
The internal control address may not exist before a projected WG interface is
applied, so its preflight checks occupied sockets; actual startup must still
bind it successfully. Preflight is advisory against external bind races; the
authenticated session binds all public mappings atomically or rolls them back.

## Runtime configuration

Both modes require `token`, `control`, `status_file`, and `mappings`. Each mapping
contains a string `id` from `"1"` through `"32"`, `protocol` (`tcp` or `udp`),
`listen`, `target`, and a nonempty `allow` array of IPv4 CIDRs. Endpoints contain
canonical IPv4 addresses and decimal ports. Hostnames, IPv6 targets, multicast,
wildcard targets, duplicate IDs/listeners, and unknown fields are rejected.
Loopback targets are permitted for deliberately exported local services.

Client mode additionally requires `socks` to be an IPv4 loopback endpoint.
`target_mark` optionally applies Linux `SO_MARK` to client-side target sockets;
the integration uses it to keep local/LAN service connections out of outbound
policy routing. Server mode rejects these client-only options.

Configuration files and their containing directories are private to root. The
firmware generates and validates them; users configure the device's mapping
table rather than editing these worker files.

## Wire protocol and authorization

1. Client opens a SOCKS5 TCP stream through HY2 to the internal control endpoint.
2. A length-prefixed JSON `control` handshake carries protocol version 2, the
   independent 256-bit token, and a SHA-256 digest of canonical shared mappings.
   Token comparison uses the standard library's constant-time comparison.
3. Server admits only one authenticated control session per worker. A second
   healthy client cannot replace it. All mapping sockets must bind successfully
   before `ready` is returned with a fresh 128-bit random session identifier.
4. The server sends `ping`; the client returns `pong` for that session. A lost
   control connection or missed heartbeat revokes listeners and active jobs.
5. An allowed external TCP connection or UDP source association creates a
   bounded job with a fresh random identifier. Server sends `open` containing
   only its session, job, and mapping IDs. It never supplies an arbitrary target
   address to the client: the client uses its locally imported mapping table.
6. Client connects to the approved target, then opens a separate SOCKS5/HY2 work
   stream. Its authenticated `work` header binds the token, mapping digest,
   session, job, mapping ID, and target-connect result. Only a pending job can
   claim it once. Replay, duplicate work, wrong mapping, and stale sessions fail.
   A failed target connection is also acknowledged before its short work
   stream closes; this prevents a buffered HY2 carrier from dropping the error
   report. The client keeps its independently observed target error if that
   acknowledgement is lost.
7. After `attached`, TCP uses a two-byte big-endian frame header: lengths 1
   through 32,768 carry that many payload bytes, 0 is logical FIN, and 65,535
   acknowledges the peer's FIN after its preceding bytes reach the local
   socket. Other lengths, repeated FIN/ACK, premature ACK, and data after FIN
   are rejected. Only the local user/target TCP socket is half-closed. The HY2
   work stream stays open until both logical FINs are acknowledged, including
   when the carrier closes both directions on transport EOF. Protocol 1 raw
   TCP work streams are rejected during the initial version handshake.
   UDP retains a two-byte big-endian payload length followed by one datagram;
   empty datagrams and payloads through 65,507 bytes are preserved.

JSON messages are capped at 8 KiB. JSON framing has a four-byte big-endian length
and does not buffer into subsequent TCP/UDP payload. The canonical mapping
digest includes listener, protocol, target, source ACLs, and IDs. Changing any
of these requires a matching new import; mismatched configurations fail closed.
The firmware also rotates the independent token when mapping semantics change.

Public source ACLs are checked before allocating a job. Target failures are
reported independently of control-channel health. The worker caps each device
at 32 mappings, 64 pending/active jobs, and 32 UDP source associations. UDP queues
hold at most two datagrams per association; overload is dropped rather than
creating unbounded memory growth. UDP associations expire after 60 seconds of
inactivity. Control heartbeats run every 10 seconds with a 35-second timeout;
pending work expires after 20 seconds. Client reconnect backoff is bounded at
15 seconds. The runtime uses two scheduler threads and a 32 MiB soft Go memory
limit, in addition to explicit protocol/session bounds.

UDP datagrams in this feature travel inside reliable reverse work streams. This
can introduce head-of-line delay; it is not the same latency or loss behavior as
direct Hysteria UDP forwarding. This feature does not provide ICMP, broadcast
discovery, original external source-IP preservation at the LAN target, or an
arbitrary layer-3 route to the client subnet.

## Status and lifecycle

Status is replaced atomically with mode `0600` and contains no token or raw
configuration. `config_sha256` hashes the **exact raw configuration file bytes**;
`pid` identifies the writer. Consumers must additionally verify executable,
process-start ticks, matching live config, and snapshot freshness before showing
online. Status alone is not a process-liveness check.

States are `initializing`, `waiting`, `connecting`, `online`, `error`, and
`stopped`. `connected` means an authenticated, configuration-matched control
session. `last_heartbeat` and `updated_at` are Unix timestamps. A mapping reports
`listening`, `active`, payload `rx_bytes`/`tx_bytes`, `last_error`, and
`last_success`. Client `listening` mirrors the server's successful registration,
not a public listener on the client. For TCP, successful target connection
updates `last_success`; for UDP, an actual target response is required.

Snapshots are coalesced to at most one per second during normal operation and
are refreshed even while offline. Shutdown writes a final `stopped` snapshot
after closing jobs/listeners. SIGTERM, SIGINT, and SIGHUP perform cleanup.

## Tests and validation boundary

```sh
cd materials/native-src/hy2-reverse
/path/to/go1.26.4/bin/go test -race -count=1 -timeout=90s ./...
```

Tests use real loopback TCP/UDP sockets and a SOCKS5 fixture. They cover full
duplex/half-close payloads (including a carrier that fully closes on either
EOF), bounded TCP frames, empty and large UDP datagrams, queue/association
lifecycle, authentication/digest checks, replay/stale sessions, duplicate login,
heartbeat expiry, source ACLs, target failure, no direct fallback, all-or-none
listener binding, automatic reconnect, private status, shutdown, and process
socket ownership for port preflight. These tests validate the worker; they do
not substitute for the repository's real sing-box, firmware boot, native
firewall, configuration upgrade, and browser acceptance tests.
