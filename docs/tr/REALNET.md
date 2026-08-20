# meshlink — Gerçek İnternet NAT Doğrulaması (Faz 4 artığı)

Demo, NAT davranışını `natbox` ile (fullcone/restricted/symmetric)
**simüle eder**. Doğrulamayı kapatmak için aynı akışın **gerçek bir ağ**
üzerinde çalıştığı gösterilmelidir:

- En az bir cone/restricted çiftinde **doğrudan delik delme (path=direct)**,
- Doğrudan yol başarısız olduğunda **relay düşüşü (path=relay)**.

Ayrıca TUN köprüsü, root gerektiren gerçek bir uçtan uca testle doğrulanır
(`make tun-demo`, tek makinede).

## Kurulum — genel sunucu (coordinator + relay)

En basiti: ucuz bir VPS (bulut ~$5/ay) + istemci tarafında iki farklı ağ
(örn. ev Wi-Fi'i + cep telefonundan tethering).

1. Sunucu ikili dosyalarını çapraz derleyin (linux/amd64):

   ```sh
   make build
   GOOS=linux GOARCH=amd64 go build -o bin/linux/coordinator ./cmd/coordinator
   GOOS=linux GOARCH=amd64 go build -o bin/linux/relay       ./cmd/relay
   GOOS=linux GOARCH=amd64 go build -o bin/linux/agent       ./cmd/agent
   scp bin/linux/{coordinator,relay,agent} user@vps:/opt/meshlink/
   ```

2. Güvenlik grubunda açın: TCP **19200**, UDP **19201**, UDP **19205**
   (0.0.0.0/0; üretimde kaynağa göre kısıtlayın).

3. Sunucuda çalıştırın:

   ```sh
   # koordinatör: ilk çalıştırmada anahtarını üretir ve yazdırır
   bin/coordinator -ctrl 0.0.0.0:19200 -stun 0.0.0.0:19201 -keyfile coord.key
   # relay
   bin/relay -addr 0.0.0.0:19205
   ```

   Çıktıdaki `control public key ...: <hex>` anahtarını not edin — bu,
   **istemcilere** `--coord-pubkey` olarak verilir.

## İstemciler — iki farklı ağda

4. İstemci ikili dosyalarını derleyin (makine başına): macOS için `GOOS=darwin
   GOARCH=amd64` (veya `arm64`), Linux için `GOOS=linux`.

5. Makine A'da (veri soketini `0.0.0.0`'a bağlayın — STUN gerçek kaynak IP'yi
   görmelidir; `127.0.0.1`'e bağlanırsa hiçbir delik açılamaz):

   ```sh
   bin/agent up --name a --keyfile key.a \
     --coordinator VPS_IP:19200 --coord-pubkey <hex> \
     --stun VPS_IP:19201 --relay VPS_IP:19205 \
     --data 0.0.0.0:19501
   ```

   Doğrulama: günlükteki `public endpoint (STUN)` satırı **public** bir adres
   göstermelidir (127.0.0.1 değil). Ev NAT'ı için bu WAN IP'si olmalıdır.

6. Makine B'yi `--name b --data 0.0.0.0:19502` ile aynı şekilde başlatın.

7. B'den çalıştırın:

   ```sh
   bin/agent ping --name b --keyfile key.b --peer a \
     --coordinator VPS_IP:19200 --coord-pubkey <hex> \
     --stun VPS_IP:19201 --relay VPS_IP:19205 \
     --data 0.0.0.0:19502 --count 3 --interval 1s
   ```

Beklenen sonuçlar:

| Senaryo | NAT'lar | Beklenen yol |
|---|---|---|
| İki ev/ADSL NAT'ı | fullcone / restricted | `direct` |
| Tethering / mobil | symmetric (veya finansal) | `relay` |
| Karma | restricted + symmetric | `relay` |

`path=relay` görünürse sistem **doğru çalışıyor** demektir — mobil NAT'larda
delik delme yapılamaz ve relay düşüşü trafiği ayakta tutar. Her iki durum da Faz
4 için geçerli doğrulamadır: hangi yol kullanılırsa kullanılsın
`received=count` sağlanmalıdır.

## Gerçek bir ağda TUN kullanımı

Delik/relay yolu tamamen aynı çalışır; yalnızca her istemciye bir overlay
adresi verin:

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

(Linux'ta `/dev/net/tun` + `ip addr add ... dev meshlink0` kullanılır; ayrıntılar
ve macOS host-route notları `docs/tr/TUN.md` içindedir.)

## Yerel ön doğrulama (root yeterli, VPS gerekmez)

```sh
make tun-demo        # iki utun açar, host route'larla tünelden ICMP geçirir
```

## Sorun giderme

| Belirti | Olası neden | Çözüm |
|---|---|---|
| STUN uç noktası `127.0.0.1` | `--data 127.0.0.1:...` kullanıldı | `--data 0.0.0.0:19501` |
| El sıkışma zaman aşımı (kontrol) | `--coord-pubkey` yanlış/eksik | `<hex>`'i sunucu günlüğünden kopyalayın |
| `ping`: yanıt yok | 19200/19201/19205 kapalı | VPS güvenlik grubunu açın |
| `path=relay` ama paket kaybı | relay'den istemciye gelen UDP kapalı | A/B makinelerinde yerel güvenlik duvarında 19501/19502 için gelen UDP'ye izin verin |
| TUN ping %100 kayıp | `<peer>` overlay adresi tutarsız | `-tun-peer` her iki tarafta da simetrik olmalıdır |

## Güvenlik notu

0.0.0.0/0 doğrulama için açılır; sonrasında relay/coordinator, `docs/tr/THREAT_MODEL.md`
bölüm 6'daki "kabul edilen riskler" çerçevesinde bir beyaz listeye veya erişim
kontrolüne taşınmalıdır (relay rate-limiting/imza sabitleme kodda zaten etkindir).
