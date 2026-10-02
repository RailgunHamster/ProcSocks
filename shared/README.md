# Shared SOCKS5 UDP implementation

`udp.rs` is compiled into both platform projects with a relative module path.
It implements RFC 1928 UDP ASSOCIATE, IPv4/IPv6/domain datagram headers,
username/password negotiation, source-port isolation, TCP-control lifetime and
idle cleanup. Fragmented **SOCKS** datagrams (`FRAG != 0`) are dropped, as allowed
by RFC 1928. macOS separately reassembles ordinary IPv4/IPv6 IP fragments before
SOCKS encapsulation.

An upstream rejecting UDP causes startup failure when `redirectUdp` is enabled.
A selected UDP flow never falls back to direct delivery after relay failure.
UDP payload bytes, excluding SOCKS and network headers, join the Mac per-process
traffic counters only after a successful upstream send / application delivery.

The relay uses a separate UDP socket per TCP association, validates the client's
IP/port, connects its outbound socket to the upstream relay and bounds the number of
explicit associations to 256. Mac associations expire after 120 seconds of
inactivity. Windows associations last until the application closes their TCP
control connection, so a live application UDP socket continues working after
an idle period. Upstream failures discard traffic and reconnect on the next
valid client datagram without closing that local control connection.

Protocol reference: [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html).
