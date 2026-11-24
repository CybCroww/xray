# Mobile Xray core

On iOS, embed `CVPNCore.xcframework` in the Packet Tunnel extension and compile
[`ios/CVPNPacketFlow.m`](ios/CVPNPacketFlow.m) with that target. Build with
`bash mobile/ios/build.sh` on a Mac with Xcode. The `iOS core` workflow checks the
native bridge and produces a ZIP containing the device and simulator slices.

Before saving the host app's `NETunnelProviderProtocol`, apply
`CVPNRequireProtectedRouting`. This enables Apple's `includeAllNetworks`;
it still has Apple's system exceptions and is not supervised Always On VPN.
Do not remove or reapply routes on a network change. Use `CVPNFullTunnelSettings`
for default IPv4 and IPv6 routes and a catch-all DNS resolver. The provided
resolver IPs are destinations inside the tunnel, not direct bootstrap servers.
Retain a `CVPNPacketFlow` built with `initWithProvider:` and call
`startWithConfig:mtu:resolverIPs:completion:`. It checks the current VPN profile
and applies tunnel settings before starting the core.
Call `stopWithCompletion:` from the provider's stop callback.

The bridge requests the protected core profile. Pass one `tun` inbound and
supported TLS/REALITY VPN outbounds; put their resolved endpoint IPs in their
addresses and retain the TLS server names. The core rejects direct fallbacks
and core-local DNS. Leave VLESS background preconnect disabled.
When the native network path changes the core clears stale
XHTTP, gRPC and Hysteria clients and resets app flows without tearing down the
packet tunnel or changing the endpoint. It cancels old flow contexts before
retiring the transport pools and admitting new flows. TCP streams that lost
their remote path still have to reconnect. The monitor uses system events
without probes.
When iOS reports an unavailable path, the bridge drains and discards app
packets while the core cancels old flows. Tunnel routes stay installed and
new packets are accepted as soon as iOS reports that a path can be used or
activated by a connection. The diagnostic snapshot exposes `networkOffline`.
The bridge only uses public packet flow APIs and keeps a single pending read.
It delivers each read to Go in batches using one reusable 16 KiB buffer, with
no timer or wait for additional packets. `inputCalls` counts queue submissions.

The extension has a 32 MiB Go runtime soft target by default. Packet storage is
bounded independently of the garbage collector: a 128-packet input ring,
capped TUN flow/queue sizes, a 512 KiB budget for incomplete IP packet buffers,
a 2 MiB budget for queued UDP buffers (256 KiB per flow), and XHTTP upload
limits. XHTTP `packet-up` has a 2 MiB shared budget for pending uplink
buffers, with one pending packet per flow. At most 24 HTTP uploads can
be in flight across the process. Writes wait for queue capacity when the
peer stalls, and closing the flow returns its buffers and cancels its
requests. XHTTP keeps the configured uplink
method, session/payload placement, authentication, host and path. The smaller
packet sizes reduce the maximum transfer rate at a given request interval, so
measure throughput in addition to memory before changing these defaults.
The mobile build uses smaller receive windows for gRPC, Hysteria and HTTP/3.
In gRPC multi-mode the decoder assembles protobuf fields into reusable 8 KiB
buffers so small writes can share storage and large reads can release it in
parts. The same gRPC servers and stream format work with this decoder.
For QUIC clients it uses standard transport parameters so that the Chrome
preset cannot override these windows. The smaller windows can constrain peak
throughput on high-latency links.

`takeMemorySnapshot:` reports the iOS process footprint, available process
memory, Go memory, packet drops, network changes, and logical XHTTP upload
requests and bytes (excluding wire overhead). XHTTP combines writes already
waiting at send time, without extending the configured interval, and avoids
duplicate TCP keepalives when HTTP/2 liveness checks are enabled. A warning
trims idle XHTTP and gRPC channels. Mobile gRPC connects on demand and enters
idle mode after 30 seconds without RPCs. A critical pressure event also asks
Go to release unused pages (rate limited).
The Go memory target is not an iOS memory cap.

`go test ./mobile -run TestProtectedTunnelTrafficStaysOnVPN` checks TUN traffic
over RAW, gRPC and XHTTP on loopback. It covers IPv4 and IPv6 DNS, TCP, withheld
VPN responses and recovery after a path change.

Before release, run on a signed physical iPhone: sustained XHTTP upload and
download, multiple simultaneous streams, a slow endpoint, Wi-Fi/cellular
switches, and repeated start/stop. Record peak and post-idle footprint,
available process memory, packet drops, throughput and any jetsam reports.
The simulator helps check integration, but cannot establish the real-device
memory headroom or whether the app outperforms a different client.
