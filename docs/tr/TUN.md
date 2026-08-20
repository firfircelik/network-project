# meshlink TUN (Gerçek Veri Taşıma)

Faz 4 hedefi (G6): gerçek IP trafiğini şifreli oturumlar üzerinden taşımak.
`agent up` bir TUN arayüzü açar (macOS `utunN`, Linux `/dev/net/tun`),
arayüzden okuduğu IP paketlerini overlay adres tablosuna göre doğru eşin
şifreli oturumuna yönlendirir; ayrıca eşlerden gelen şifresi çözülmüş paketleri
arayüze yazar.

## Doğrulama

- **Tek makine (root yeter):** `make tun-demo` — tek makinede iki utun
  + iki `agent up`, ICMP trafiği `-host`/`ip route` ile tünelden geçirilir ve
  `ping 10.62.0.2` doğrulanır (scr: `scripts/tun-demo.sh`).
- **Gerçek internet:** iki farklı ağdaki istemciler + genel bir VPS üzerinde
  coordinator/relay → `docs/tr/REALNET.md`.

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

- `internal/tun`: TUN cihaz erişimi (`Device`) + IPv4 yönlendirme (`Router`)
  + testler için bellek içi bir cihaz (`BufferDevice`).
- `internal/agent/tunbridge.go`: cihaz ile eş oturumları arasındaki köprü.
- Overlay adres atamaları `-tun-peer <id>=<ip>` ile verilir; isim koordinatörden
  öğrenildiğinde rota kurulur.

## macOS kurulum ve çalıştırma adımları (root gerektirir)

1. Koordinatörü derleyin ve başlatın:

   ```sh
   make build
   bin/coordinator -keyfile bin/coord.key
   ```

   Çıktıdaki `control public key ...: <hex>` değerini not edin.

2. Ajan "a" tarafı (utun9):

   ```sh
   bin/agent up --name a --keyfile bin/key.a \
     --coord-pubkey <hex> --stun 127.0.0.1:19201 \
     --relay 127.0.0.1:19205 --data 127.0.0.1:19501 \
     --tun utun9 --tun-ip 10.60.0.1 --tun-peer b=10.60.0.2
   sudo ifconfig utun9 10.60.0.1/24 up
   ```

3. Ajan "b" tarafı (utun10):

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

## Linux kurulum ve çalıştırma adımları

Aynı bayraklar; TUN cihazı `internal/tun/tun_linux.go` üzerinden
`/dev/net/tun` (IFF_TUN|IFF_NO_PI) kullanır. İsim boş bırakılırsa çekirdek
boş bir arayüzü `meshlink%d` olarak açar:

```sh
sudo ip tuntap add dev meshlink0 mode tun
bin/agent up --name a ... --tun meshlink0 --tun-ip 10.60.0.1 --tun-peer b=10.60.0.2
sudo ip addr add 10.60.0.1/24 dev meshlink0
sudo ip link set meshlink0 up
```

## Makineler arası test — aynı LAN üzerinde Linux + macOS

İki ayrı makine, iki ayrı işletim sistemi, aynı ağ: ajanlar birbirlerini
doğrudan delik delmeyle görür (`path=direct`) ve overlay üzerinden birbirlerine
ping atar. Hat formatı tüm uzunluk alanlarında big-endian olduğundan platform
farkı yoktur; yalnızca cihaz adı ve arayüz komutu işletim sistemine özgüdür.
Burada `/32` rotaları da gereklidir — aksi halde çekirdek overlay hedefini
varsayılan ağ geçidi üzerinden denemeye çalışır.

Mac (örn. `192.168.1.10`): coordinator + relay + agent a

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

Linux (örn. `192.168.1.20`): agent b

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

Her iki tarafta da `ping` kayıpsızsa ve günlüklerdeki `public endpoint (STUN)`
satırı diğer makinenin LAN IP'sini gösteriyorsa, **platformlar arası mesh
doğrulanmıştır (`path=direct`)**. Aynı tarif gerçek internet için de geçerlidir;
tek fark coordinator/relay'in genel bir VPS üzerinde olmasıdır
(`docs/tr/REALNET.md`).

## Sınırlar ve ayrıntılar

- Overlay adresleri statik bir `-tun-peer` tablosuyla yönetilir (WireGuard
  `AllowedIPs` benzeri); dinamik tahsis "v1.1+" listesindedir.
- Yönlendirme düz IPv4 içindir (L3 TUN); L2 (TAP)/IPv6 daha sonraki bir sürümde.
- TUN erişimi root gerektirir; testler `BufferDevice` ile rootsuz çalışır ve
  gerçek bir cihaz açılamazsa test `t.Skip` ile atlanır.
- Yönlendirme tablosunda olmayan hedefler sessizce atılır (`PktsDropped`);
  `Pings/Routed/Dropped` sayaçları `Router` üzerinde tutulur.
