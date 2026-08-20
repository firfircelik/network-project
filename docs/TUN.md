# meshlink TUN (Real Data Transport)

Phase 4 goal (G6): carry real IP traffic over encrypted sessions.
`agent up` opens a TUN interface (macOS `utunN`, Linux `/dev/net/tun`),
routes the IP packets it reads from the interface to the correct peer's
encrypted session according to the overlay address table; it also writes
decrypted packets coming from peers to the interface.

## Verification

- **Single machine (root suffices):** `make tun-demo` — two utun
  + two `agent up` on a single machine, ICMP traffic is forced through the
  tunnel with `-host`/`ip route` and `ping 10.62.0.2` is verified (scr: `scripts/tun-demo.sh`).
- **Real internet:** clients on two different networks + coordinator/relay
  on a public VPS → `docs/REALNET.md`.

## Architecture

```
                    ┌──────────────────────────── agent ────────────────────────────┐
  OS routing table  │                                                              │
  dst 10.60.0.2 ──► │ TUN device ──► tun.Router ──(dest IP lookup)──► peer.Send()   │ ─► Noise sessi
    (utun9, dev)    │                    ▲                                           │
                    │                    │          decrypted payloads (p.Recv())    │
                    │                    └──────────── tunnel bridge ────────────────┘ ◄─ Noise session
                    └──────────────────────────────────────────────────────────────┘
```

- `internal/tun`: TUN device access (`Device`) + IPv4 routing (`Router`)
  + an in-memory device for tests (`BufferDevice`).
- `internal/agent/tunbridge.go`: the bridge between the device and peer sessions.
- Overlay address assignments are given with `-tun-peer <id>=<ip>`; as the
  name is learned from the coordinator, the route is installed.

## macOS setup and run steps (requires root)

1. Build and start the coordinator:

   ```sh
   make build
   bin/coordinator -keyfile bin/coord.key
   ```

   Note the `control public key ...: <hex>` value in the output.

2. Agent "a" side (utun9):

   ```sh
   bin/agent up --name a --keyfile bin/key.a \
     --coord-pubkey <hex> --stun 127.0.0.1:19201 \
     --relay 127.0.0.1:19205 --data 127.0.0.1:19501 \
     --tun utun9 --tun-ip 10.60.0.1 --tun-peer b=10.60.0.2
   sudo ifconfig utun9 10.60.0.1/24 up
   ```

3. Agent "b" side (utun10):

   ```sh
   bin/agent up --name b --keyfile bin/key.b \
     --coord-pubkey <hex> --stun 127.0.0.1:19201 \
     --relay 127.0.0.1:19205 --data 127.0.0.1:19502 \
     --tun utun10 --tun-ip 10.60.0.2 --tun-peer a=10.60.0.1
   sudo ifconfig utun10 10.60.0.2/24 up
   ```

4. Test:

   ```sh
   ping -c 3 10.60.0.2   # on laptop a: ICMP to b passes through the tunnel
   ```

## Linux setup and run steps

Same flags; the TUN device uses `/dev/net/tun` (IFF_TUN|IFF_NO_PI) via
`internal/tun/tun_linux.go`. If the name is left empty, the kernel opens a
free interface as `meshlink%d`:

```sh
sudo ip tuntap add dev meshlink0 mode tun
bin/agent up --name a ... --tun meshlink0 --tun-ip 10.60.0.1 --tun-peer b=10.60.0.2
sudo ip addr add 10.60.0.1/24 dev meshlink0
sudo ip link set meshlink0 up
```

## Cross-machine test — Linux + macOS on the same LAN

Two separate machines, two separate OSes, same network: the agents see each
other by direct hole punching (`path=direct`) and ping each other over the
overlay. Since the wire format is big-endian in all length fields, there is
no platform difference; only the device name and the interface command are
OS-specific. Route `/32`s are also required here — otherwise the kernel
tries the overlay destination via the default gateway.

Mac (e.g. `192.168.1.10`): coordinator + relay + agent a

```sh
bin/coordinator -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile coord.key &
bin/relay -addr 0.0.0.0:19205 &
# read <coord_pub_hex> from the output

bin/agent up --name a --keyfile key.a \
  --coordinator 192.168.1.10:19200 --coord-pubkey <coord_pub_hex> \
  --stun 192.168.1.10:19201 --relay 192.168.1.10:19205 \
  --data 0.0.0.0:19501 \
  --tun utun9 --tun-ip 10.61.0.1 --tun-peer b=10.62.0.2
sudo ifconfig utun9 10.61.0.1/24 up
sudo route add -host 10.62.0.2 -interface utun9
ping -c 3 10.62.0.2
```

Linux (e.g. `192.168.1.20`): agent b

```sh
bin/agent up --name b --keyfile key.b \
  --coordinator 192.168.1.10:19200 --coord-pubkey <coord_pub_hex> \
  --stun 192.168.1.10:19201 --relay 192.168.1.10:19205 \
  --data 0.0.0.0:19501 \
  --tun meshlink_b --tun-ip 10.62.0.2 --tun-peer a=10.61.0.1
sudo ip addr add 10.62.0.2/24 dev meshlink_b
sudo ip link set meshlink_b up
sudo ip route add 10.61.0.1/32 dev meshlink_b
ping -c 3 10.61.0.1
```

On both sides, if `ping` is lossless and the `public endpoint (STUN)` line
in the logs shows the other machine's LAN IP, **cross-platform mesh is
verified (`path=direct`)**. The same recipe applies to the real internet;
the only difference is that the coordinator/relay is on a public VPS
(`docs/REALNET.md`).

## Limits and details

- Overlay addresses are managed with a static `-tun-peer` table (WireGuard
  `AllowedIPs`-like); dynamic allocation is on the "v1.1+" list.
- Routing is for plain IPv4 (L3 TUN); L2 (TAP)/IPv6 in a later version.
- TUN access requires root; tests run rootless with `BufferDevice`, and if
  no real device can be opened, the test is skipped with `t.Skip`.
- Destinations not in the routing table are silently dropped (`PktsDropped`);
  the `Pings/Routed/Dropped` counters are kept on `Router`.
