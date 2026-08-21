# meshlink — Real-Internet NAT Verification (Phase 4 leftover)

The demo **simulates** NAT behavior with `natbox` (fullcone/restricted/
symmetric). To close out the verification, the same flow must be shown
running over a **real network**:

- **Direct hole punching (path=direct)** on at least one cone/restricted pair,
- **Relay fallback (path=relay)** when the direct path fails.

Also, the TUN bridge is verified with a real e2e that requires root
(`make tun-demo`, on a single machine).

## LAN quickstart — two devices, no VPS

The fastest way to answer "do two devices see each other?" is over the same
Wi-Fi/LAN, where direct paths need no NAT traversal:

```sh
make lan-demo
```

This starts coordinator + relay on this machine, binds both agent sockets to
`0.0.0.0`, and pings through the **real LAN/wireless interface** — expected
result `path=direct`. It also prints a one-shot `agent status` snapshot and the
exact commands to copy onto a second device:

- Device A (daemon): `bin/agent up --name a ...`
- Device B (one-shot): `bin/agent ping --name b ... --peer a`
- Device B (live dashboard): `bin/agent tui --name b ...`

For the LAN the coordinator/relay can run on either device; every command must
use that machine's `LAN_IP` and the coordinator's `<hex>` pubkey. If the IP is
not auto-detected, pass `LAN_IP=192.168.x.y make lan-demo`.

## Queries and dashboards

- `bin/agent status --name <id> ...` prints a one-shot snapshot (local
  key/endpoint, coordinator registry counters, per-peer path/RTT/rekeys)
  and exits. Add `--json` for a machine-readable JSON document on stdout
  (logs stay on stderr) and `--probe-peer <id>` to ping one peer first so
  the report contains a real path/RTT.
- `bin/agent tui    --name <id> ...` opens the live terminal dashboard (same
  fields, refreshed every second, RTT history).

Both reuse the same flags as `up`/`ping` (`--coordinator`, `--coord-pubkey`,
`--stun`, `--relay`, `--data`).

## Setup — public server (coordinator + relay)

Simplest: a cheap VPS (cloud ~$5/month) + two different networks on the client
side (e.g. home Wi-Fi + tethering from a mobile phone).

1. Cross-compile the server binaries (linux/amd64):

   ```sh
   make build
   GOOS=linux GOARCH=amd64 go build -o bin/linux/coordinator ./cmd/coordinator
   GOOS=linux GOARCH=amd64 go build -o bin/linux/relay       ./cmd/relay
   GOOS=linux GOARCH=amd64 go build -o bin/linux/agent       ./cmd/agent
   scp bin/linux/{coordinator,relay,agent} user@vps:/opt/meshlink/
   ```

2. Open in the security group: TCP **19200**, UDP **19201**, UDP **19205**
   (0.0.0.0/0; restrict by source in production).

3. Run on the server:

   ```sh
   # koordinatör: ilk çalıştırmada anahtarını üretir ve yazdırır
   bin/coordinator -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile coord.key
   # relay
   bin/relay -addr 0.0.0.0:19205
   ```

   Note the `control public key ...: <hex>` key from the output — this is
   given to the **clients** as `--coord-pubkey`.

## Clients — on two different networks

4. Build the client binaries (per machine): for macOS `GOOS=darwin
   GOARCH=amd64` (or `arm64`), for Linux `GOOS=linux`.

5. On machine A (bind the data socket to `0.0.0.0` — STUN must see the real
   source IP; if bound to `127.0.0.1`, no hole can be opened):

   ```sh
   bin/agent up --name a --keyfile key.a \
     --coordinator VPS_IP:19200 --coord-pubkey <hex> \
     --stun VPS_IP:19201 --relay VPS_IP:19205 \
     --data 0.0.0.0:19501
   ```

   Verification: the `public endpoint (STUN)` line in the log must show a
   **public** address (not 127.0.0.1). For a home NAT, this should be the WAN
   IP.

6. Start machine B the same way with `--name b --data 0.0.0.0:19502`.

7. Run from B:

   ```sh
   bin/agent ping --name b --keyfile key.b --peer a \
     --coordinator VPS_IP:19200 --coord-pubkey <hex> \
     --stun VPS_IP:19201 --relay VPS_IP:19205 \
     --data 0.0.0.0:19502 --count 3 --interval 1s
   ```

Expected results:

| Scenario | NATs | Expected path |
|---|---|---|
| Two home/ADSL NATs | fullcone / restricted | `direct` |
| Tethering / mobile | symmetric (or financial) | `relay` |
| Mixed | restricted + symmetric | `relay` |

If `path=relay` appears, the system is **working correctly** — mobile NATs
cannot be hole-punched and the relay fallback keeps the traffic up. Both cases
are valid verification for Phase 4: whichever path is used, `received=count`
must hold.

## Using TUN on a real network

The hole/relay path works exactly the same; just give each client an overlay
address:

```sh
# A tarafı
bin/agent up --name a --keyfile key.a \
  --coordinator VPS_IP:19200 --coord-pubkey <hex> \
  --stun VPS_IP:19201 --relay VPS_IP:19205 \
  --data 0.0.0.0:19501 \
  --tun utun9 --tun-ip 10.61.0.1 --tun-peer b=10.62.0.2
sudo ifconfig utun9 10.61.0.1/24 up

# B tarafı
bin/agent up --name b --keyfile key.b \
  --coordinator VPS_IP:19200 --coord-pubkey <hex> \
  --stun VPS_IP:19201 --relay VPS_IP:19205 \
  --data 0.0.0.0:19502 \
  --tun utun10 --tun-ip 10.62.0.2 --tun-peer a=10.61.0.1
sudo ifconfig utun10 10.62.0.2/24 up

# B makinede overlay boyunca ping:
ping -c 3 10.61.0.1
```

(On Linux, `/dev/net/tun` + `ip addr add ... dev meshlink0` is used; details
and macOS host-route notes are in `docs/TUN.md`.)

## Local pre-verification (root is enough, no VPS)

```sh
make tun-demo        # iki utun açar, host route'larla tünelden ICMP geçirir
```

## Troubleshooting

| Symptom | Possible cause | Fix |
|---|---|---|
| `make lan-demo`: STUN endpoint `127.0.0.1` | LAN IP detection picked a loopback address | `LAN_IP=<real LAN IP> make lan-demo` |
| `make lan-demo`: can't detect IP | no active Wi-Fi/Ethernet interface | Pass `LAN_IP=...` explicitly |
| STUN endpoint `127.0.0.1` | `--data 127.0.0.1:...` was used | `--data 0.0.0.0:19501` |
| Handshake timeout (control) | `--coord-pubkey` wrong/missing | Copy the `<hex>` from the server log |
| `ping`: no response | 19200/19201/19205 closed | Open the VPS security group |
| `path=relay` but packet loss | inbound UDP from relay to client closed | Allow inbound UDP on 19501/19502 in the local firewall on machines A/B |
| `agent status`: `registry_error: no control session` | coordinator down or wrong `--coord-pubkey` | Check `bin/coordinator` log and the key hex |
| TUN ping 100% loss | `<peer>` overlay address inconsistent | `-tun-peer` must be symmetric on both sides |

## Security note

0.0.0.0/0 is opened for verification; afterwards the relay/coordinator should
be moved to a whitelist or access control under the "accepted risks" framework
in section 6 of `docs/THREAT_MODEL.md` (relay rate-limiting/signature pinning
is already active in the code).
