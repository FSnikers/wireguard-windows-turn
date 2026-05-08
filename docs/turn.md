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

## Example: VK link credential mode

```ini
[Interface]
PrivateKey = ...
Address = 10.0.0.2/32
MTU = 1280

[TURN]
Enabled = true
Mode = vk_link
Link = https://vk.com/call/join/...
Listen = 127.0.0.1:9000
Peer = vpn.example.com:51820
Streams = 4
UDP = false
PeerType = proxy_v2
StreamsPerCred = 4
WatchdogTimeout = 30

[Peer]
PublicKey = ...
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
```

## Android-style `#@wgt:` metadata

Configs exported from `wireguard-turn-android` can also enable TURN with
metadata comments inside the first `[Peer]` section. The Windows parser imports
these comments and maps them to the internal `[TURN]` settings before the tunnel
starts:

```ini
[Peer]
PublicKey = ...
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
# [Peer] TURN extensions
#@wgt:EnableTURN = true
#@wgt:UseUDP = false
#@wgt:IPPort = vpn.example.com:51820
#@wgt:VKLink = https://vk.com/call/join/...
#@wgt:Mode = vk_link
#@wgt:PeerType = proxy_v2
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000
#@wgt:StreamsPerCred = 4
#@wgt:TurnIP = 155.212.199.166
#@wgt:TurnPort = 19302
#@wgt:WatchdogTimeout = 30
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
- `Mode`: `static` for manually supplied TURN credentials, `vk_link` for VK
  Calls anonymous-link TURN credentials, or `wb` for the WB credential flow
  ported from the Android implementation.
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

## VK captcha handling

VK link mode first tries the automatic Not Robot flow and the slider proof of
concept solver. If VK still requires a user action, the service starts a local
manual captcha helper on `http://localhost:8765`, opens the default browser, and
continues after the browser page returns either a `success_token` or an image
captcha key. Only one captcha solve runs at a time so multiple TURN streams do
not open competing browser sessions.