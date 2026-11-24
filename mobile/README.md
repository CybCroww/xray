# Mobile Xray core

On iOS, embed `CVPNCore.xcframework` in the Packet Tunnel extension and compile
[`ios/CVPNPacketFlow.m`](ios/CVPNPacketFlow.m) with that target. Build with
`bash mobile/ios/build.sh` on a Mac with Xcode. The `iOS core` workflow checks the
native bridge and produces a ZIP containing the device and simulator slices.

The extension owns `NEPacketTunnelNetworkSettings`, routes and DNS. After
`setTunnelNetworkSettings` succeeds, retain a `CVPNPacketFlow` constructed from
`packetFlow`, then call `startWithConfig:mtu:completion:`. Pass one Xray `tun`
inbound and the app's desired outbound(s) in the JSON. Use the same MTU in both
places. Call `stopWithCompletion:` from the provider's stop callback. The
bridge uses only public packet flow APIs and has no dependency on utun fd
discovery. It starts exactly one outstanding native read at a time.

The extension has a 32 MiB Go runtime soft target by default. Packet storage is
bounded independently of the garbage collector: a 128-packet input ring,
capped TUN flow/queue sizes and XHTTP upload limits. A stalled XHTTP `packet-up`
peer blocks further writes once the outstanding request budget is exhausted;
closing the flow cancels the requests. XHTTP keeps the configured uplink
method, session/payload placement, authentication, host and path. The smaller
packet sizes reduce the maximum transfer rate at a given request interval, so
measure throughput in addition to memory before changing these defaults.

`takeMemorySnapshot:` reports the iOS process footprint, available process
memory, Go memory and packet drop counters. A warning trims idle XHTTP pools;
a critical pressure event also asks Go to release unused pages (rate limited).
The Go memory target is not an iOS memory cap.

Before release, run on a signed physical iPhone: sustained XHTTP upload and
download, multiple simultaneous streams, a slow endpoint, Wi-Fi/cellular
switches, and repeated start/stop. Record peak and post-idle footprint,
available process memory, packet drops, throughput and any jetsam reports.
The simulator helps check integration, but cannot establish the real-device
memory headroom or whether the app outperforms a different client.
