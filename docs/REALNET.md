# meshlink — Gerçek İnternet NAT Doğrulaması (Faz 4 kalıntısı)

Demo, NAT davranışını `natbox` ile **simüle** eder (fullcone/restricted/
symmetric). Doğrulamanın kapanması için aynı akışın **gerçek ağ üzerinde**
çalıştığı gösterilmelidir:

- **Doğrudan delik delme (path=direct)** en az bir cone/restricted çiftinde,
- **Relay yedeği (path=relay)**, doğrudan yol başarısız olduğunda.

Ayrıca TUN köprüsü root gerektiren gerçek e2e ile doğrulanır
(`make tun-demo`, tek makinede).

## Kurulum — halka açık sunucu (koordinatör + relay)

En kolay: ucuz bir VPS (bulut ~5$/ay) + istemci tarafında iki farklı ağ
(ör. ev Wi-Fi + bir cep telefonundan tethering).

1. Sunucu ikililerini çapraz derle (linux/amd64):

   ```sh
   make build
   GOOS=linux GOARCH=amd64 go build -o bin/linux/coordinator ./cmd/coordinator
   GOOS=linux GOARCH=amd64 go build -o bin/linux/relay       ./cmd/relay
   GOOS=linux GOARCH=amd64 go build -o bin/linux/agent       ./cmd/agent
   scp bin/linux/{coordinator,relay,agent} user@vps:/opt/meshlink/
   ```

2. Güvenlik grubunda aç: TCP **19200**, UDP **19201**, UDP **19205** (0.0.0.0/0;
   production'da kaynak kısıtlanır).

3. Sunucuda çalıştır:

   ```sh
   # koordinatör: ilk çalıştırmada anahtarını üretir ve yazdırır
   bin/coordinator -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile coord.key
   # relay
   bin/relay -addr 0.0.0.0:19205
   ```

   Çıktıdan `control public key ...: <hex>` anahtarını not al — bu **istemcilere**
   `--coord-pubkey` olarak verilir.

## İstemciler — iki farklı ağda

4. İstemci ikililerini derle (makineye göre): macOS için `GOOS=darwin
   GOARCH=amd64` (veya `arm64`), Linux için `GOOS=linux`.

5. Makine A'da (data soketini `0.0.0.0`'a bağla — STUN'un gerçek kaynak IP'yi
   görmesi şart; `127.0.0.1`'e bağlanırsa delik açılamaz):

   ```sh
   bin/agent up --name a --keyfile key.a \
     --coordinator VPS_IP:19200 --coord-pubkey <hex> \
     --stun VPS_IP:19201 --relay VPS_IP:19205 \
     --data 0.0.0.0:19501
   ```

   Doğrulama: logdaki `public endpoint (STUN)` satırı bir **halka açık** adres
   göstermelidir (127.0.0.1 değil). Ev NAT'ı için bu, WAN IP'si olmalıdır.

6. Makine B'de aynı şekilde `--name b --data 0.0.0.0:19502` ile başlat.

7. B'den koş:

   ```sh
   bin/agent ping --name b --keyfile key.b --peer a \
     --coordinator VPS_IP:19200 --coord-pubkey <hex> \
     --stun VPS_IP:19201 --relay VPS_IP:19205 \
     --data 0.0.0.0:19502 --count 3 --interval 1s
   ```

Beklenen sonuçlar:

| Senaryo | NAT'lar | Beklenen path |
|---|---|---|
| İki ev/ADSL NAT'ı | fullcone / restricted | `direct` |
| Tethering / mobil | symmetric (veya finans) | `relay` |
| Karışık | restricted + symmetric | `relay` |

`path=relay` görünüyorsa sistem **doğru çalışıyor** demektir — mobil NAT'larda
delik açılamaz ve relay yedeği trafiği ayakta tutar. İki durum da Faz 4 için
geçerli bir doğrulamadır: hangi path olursa olsun `received=count` olmalıdır.

## TUN'ı gerçek ağda kullanma

Delik/relay yolu aynen çalışır; sadece her istemciye bir overlay adresi ver:

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

(Linux'ta `/dev/net/tun` + `ip addr add ... dev meshlink0` kullanılır; ayrıntı
ve macOS host-route notları `docs/TUN.md` içinde.)

## Yerel ön doğrulama (root yeterli, VPS yok)

```sh
make tun-demo        # iki utun açar, host route'larla tünelden ICMP geçirir
```

## Sorun giderme

| Belirti | Olası neden | Çözüm |
|---|---|---|
| STUN endpoint `127.0.0.1` | `--data 127.0.0.1:...` kullanıldı | `--data 0.0.0.0:19501` |
| Handshake timeout (control) | `--coord-pubkey` yanlış/eksik | Sunucu logundaki `<hex>`'i kopyala |
| `ping`: hiç yanıt | 19200/19201/19205 kapalı | VPS güvenlik grubunu aç |
| `path=relay` ama paket kaybı var | relay'den istemciye inbound UDP kapalı | A/B makinede yerel firewall'da 19501/19502'ye inbound UDP izin ver |
| TUN ping %100 kayıp | `<peer>` overlay adresi tutarsız | `-tun-peer` iki tarafta simetrik olmalı |

## Güvenlik notu

Doğrulama için 0.0.0.0/0 açılır; sonrasında relay/koordinatör
`docs/THREAT_MODEL.md` bölüm 6'daki "kabul edilen riskler" çerçevesinde
beyaz listeye veya erişim kontrolüne alınmalıdır (relay rate-limit/imza
pinleme zaten kodda aktiftir).