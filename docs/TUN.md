# meshlink TUN (Gerçek Veri Taşıma)

Faz 4 hedefi (G6): şifreli oturumların üzerinden gerçek IP trafiğini taşımak.
`agent up` bir TUN arabirimi açar (macOS `utunN`, Linux `/dev/net/tun`),
arabirimden okuduğu IP paketlerini overlay adres tablosuna göre doğru peer'ın
şifreli oturumuna yönlendirir; peer'lardan gelen çözülmüş paketleri de
arabirime yazar.

## Doğrulama

- **Tek makine (root yeterli):** `make tun-demo` — tek makinede iki utun
  + iki `agent up`, `-host`/`ip route` ile ICMP trafiği zorla tünelin
  içinden geçirilir ve `ping 10.62.0.2` doğrulanır (scr: `scripts/tun-demo.sh`).
- **Gerçek internet:** iki farklı ağdaki istemci + halka açık VPS üzerinde
  koordinatör/relay → `docs/REALNET.md`.

## Mimari

```
                    ┌──────────────────────────── agent ────────────────────────────┐
  OS routing table  │                                                              │
  dst 10.60.0.2 ──► │ TUN device ──► tun.Router ──(dest IP lookup)──► peer.Send()   │ ─► Noise sessi
    (utun9, dev)    │                    ▲                                           │
                    │                    │          decrypted payloads (p.Recv())    │
                    │                    └──────────── tunnel bridge ────────────────┘ ◄─ Noise session
                    └──────────────────────────────────────────────────────────────┘
```

- `internal/tun`: TUN aygıt erişimi (`Device`) + IPv4 yönlendirme (`Router`)
  + testler için bellekte aygıt (`BufferDevice`).
- `internal/agent/tunbridge.go`: aygıt ile peer oturumları arasındaki köprü.
- Overlay adres atamaları `-tun-peer <id>=<ip>` ile verilir; isim
  koordinatörden öğrenildikçe rota takılır.

## macOS kurulum ve çalıştırma adımları (root gerektirir)

1. Derle ve koordinatörü başlat:

   ```sh
   make build
   bin/coordinator -keyfile bin/coord.key
   ```

   Çıktıdaki `control public key ...: <hex>` değerini not al.

2. Agent "a" tarafı (utun9):

   ```sh
   bin/agent up --name a --keyfile bin/key.a \
     --coord-pubkey <hex> --stun 127.0.0.1:19201 \
     --relay 127.0.0.1:19205 --data 127.0.0.1:19501 \
     --tun utun9 --tun-ip 10.60.0.1 --tun-peer b=10.60.0.2
   sudo ifconfig utun9 10.60.0.1/24 up
   ```

3. Agent "b" tarafı (utun10):

   ```sh
   bin/agent up --name b --keyfile bin/key.b \
     --coord-pubkey <hex> --stun 127.0.0.1:19201 \
     --relay 127.0.0.1:19205 --data 127.0.0.1:19502 \
     --tun utun10 --tun-ip 10.60.0.2 --tun-peer a=10.60.0.1
   sudo ifconfig utun10 10.60.0.2/24 up
   ```

4. Test:

   ```sh
   ping -c 3 10.60.0.2   # a dizüstünde: b'ye giden ICMP tünelden geçer
   ```

## Linux kurulum ve çalıştırma adımları

Aynı flag'ler; TUN aygıtı `internal/tun/tun_linux.go` üzerinden
`/dev/net/tun` (IFF_TUN|IFF_NO_PI) kullanır. İsim boş bırakılırsa çekirdek
`meshlink%d` ile serbest bir arabirim açar:

```sh
sudo ip tuntap add dev meshlink0 mode tun
bin/agent up --name a ... --tun meshlink0 --tun-ip 10.60.0.1 --tun-peer b=10.60.0.2
sudo ip addr add 10.60.0.1/24 dev meshlink0
sudo ip link set meshlink0 up
```

## Çapraz makine testi — Linux + macOS aynı LAN'da

İki ayrı makine, iki ayrı OS, aynı ağ: agent'lar birbirini doğrudan delik
açarak görür (`path=direct`) ve overlay üzerinden ping'leşir. Wire format tüm
uzunluk alanlarında big-endian olduğu için platform farkı yoktur; yalnızca
aygıt adı ve arayüz komutu OS'e özeldir. Route `/32`'ler burada da gereklidir —
aksi halde kernel overlay hedefini default gateway üzerinden dener.

Mac (ör. `192.168.1.10`): koordinatör + relay + agent a

```sh
bin/coordinator -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile coord.key &
bin/relay -addr 0.0.0.0:19205 &
# çıktıdan <coord_pub_hex>'i oku

bin/agent up --name a --keyfile key.a \
  --coordinator 192.168.1.10:19200 --coord-pubkey <coord_pub_hex> \
  --stun 192.168.1.10:19201 --relay 192.168.1.10:19205 \
  --data 0.0.0.0:19501 \
  --tun utun9 --tun-ip 10.61.0.1 --tun-peer b=10.62.0.2
sudo ifconfig utun9 10.61.0.1/24 up
sudo route add -host 10.62.0.2 -interface utun9
ping -c 3 10.62.0.2
```

Linux (ör. `192.168.1.20`): agent b

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

Her iki tarafta da `ping` kayıpsız ve loglarda `public endpoint (STUN)` satırı
karşı makinenin LAN IP'sini gösterirse **çapraz-platform mesh doğrulanmıştır
(`path=direct`)**. Aynı tarif gerçek internet için de geçerlidir; tek fark
koordinatör/relay'in halka açık bir VPS'te olması (`docs/REALNET.md`).

## Sınırlar ve ayrıntılar

- Overlay adresleri statik `-tun-peer` tablosuyla yönetilir (WireGuard
  `AllowedIPs` benzeri); dinamik tahsis "v1.1+" listesindedir.
- Yönlendirme düz IPv4 içindir (L3 TUN); L2 (TAP)/IPv6 sonraki sürümde.
- TUN erişimi root gerektirir; testler `BufferDevice` ile root'suz koşar,
  gerçek aygıt açılışı yoksa test `t.Skip` ile atlanır.
- Yönlendirme tablosunda olmayan hedefler sessizce düşer (`PktsDropped`);
  `Pings/Routed/Dropped` sayaçları `Router` üzerinde tutulur.