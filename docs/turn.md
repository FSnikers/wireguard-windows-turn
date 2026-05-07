# TURN transport

WireGuard for Windows can run a local TURN proxy before the tunnel adapter is
configured. When `[TURN]` is enabled, the service starts a UDP listener on the
configured local endpoint and rewrites the single WireGuard peer endpoint to that
listener. The proxy then relays packets to the original WireGuard server through
a TURN allocation, optionally wrapping packets in DTLS and sending the same
session/stream handshake used by `wireguard-turn-android`.

Only one WireGuard peer is supported while TURN mode is enabled.

## Example: static TURN credentials

```ini
[Interface]
PrivateKey = ...
Address = 10.0.0.2/32

[TURN]
Enabled = true
Mode = static
Listen = 127.0.0.1:51820
Peer = vpn.example.com:51820
Streams = 4
UDP = true
PeerType = proxy_v2
TurnUsername = user
TurnPassword = pass
TurnServer = turn.example.com:3478

[Peer]
PublicKey = ...
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
```

## Example: WB credential mode

```ini
[TURN]
Enabled = true
Mode = wb
Listen = 127.0.0.1:51820
Streams = 4
UDP = true
PeerType = proxy_v2
StreamsPerCred = 4
WatchdogTimeout = 60
```

## Keys

- `Enabled`: enables the proxy when set to `true`, `yes`, or `1`.
- `Mode`: `static` for manually supplied TURN credentials or `wb` for the WB
  credential flow ported from the Android implementation.
- `Listen`: local UDP endpoint used by WireGuardNT.
- `Peer`: real WireGuard server endpoint. If omitted, the existing `[Peer]`
  `Endpoint` is used.
- `Streams`: number of parallel TURN allocations.
- `UDP`: use UDP transport to the TURN server when true; TCP is used otherwise.
- `PeerType`: `proxy_v2` for DTLS plus session/stream handshake, `proxy_v1` for
  DTLS without that handshake, or `wireguard` for direct relay without DTLS.
- `TurnIP` / `TurnPort`: optional overrides for the TURN server returned by the
  credential provider.
- `StreamsPerCred`: number of streams sharing one cached credential in dynamic
  credential modes.
- `WatchdogTimeout`: DTLS receive watchdog in seconds; `0` disables it.
- `TurnUsername`, `TurnPassword`, `TurnServer`: required in `static` mode.
