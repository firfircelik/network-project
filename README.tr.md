# meshlink

**🌐 Languages:** [English](README.md) · [Türkçe](README.tr.md) · [Français](README.fr.md) · [Italiano](README.it.md) · [Deutsch](README.de.md)

Go ile yazılmış, şifreli ve NAT aşan P2P mesh VPN. Ajanlar Noise-XX
şifreli tüneller üzerinden haberleşir, STUN + eşzamanlı açılış delik delme ile
NAT'ları aşar ve doğrudan bir yol imkânsız olduğunda bir relay'e düşer —
yerleşik bir NAT simülatörü içerdiği için tüm yığın localhost üzerinde root
gerektirmeden çalışır.

## Özellikler

- **Uçtan uca şifreleme** — Noise Protocol Framework, XX deseni,
  X25519 + ChaCha20-Poly1305 + SHA256. Relay yalnızca ciphertext'i iletir;
  şifre çözme iki uç noktada gerçekleşir.
- **Kimliği doğrulanmış kontrol düzlemi** — ajan ↔ koordinatör oturumları
  Noise-XX ile şifrelidir ve ajan koordinatörün statik anahtarını sabitler
  (`--coord-pubkey`); böylece kayıtlar ve eş listeleri ağ üzerinde
  gözlemlenemez veya yeniden yazılamaz.
- **Tekrar koruması + kayıp toleransı** — her DATA çerçevesi açık bir
  64-bit nonce ile başlar; alıcı bunu WireGuard tarzı 2048 girişlik kayan
  pencereyle kabul eder (sıra dışı geliş tolere edilir, tekrarlar ve eski
  nonce'lar atılır). Periyodik rekey anahtarları belirleyici (deterministik)
  biçimde, bir rekey-DoS kapağıyla döndürür.
- **NAT aşımı** — STUN uç nokta keşfi artı full-cone ve adres-kısıtlı
  NAT'lar için eşzamanlı açılış delik delme; symmetric-NAT oturumlarını canlı
  tutmak için relay düşüşü ve yeniden yoklama.
- **Relay sertleştirmesi** — kaynak başına pps/byte hız limitleri, isim
  başına kotalar ve isim→adres sabitleme.
- **Gerçek trafik (TUN)** — L3 TUN köprüsü (macOS `utun`, Linux
  `/dev/net/tun`) IPv4 paketlerini şifreli oturumlar üzerinden yönlendirir;
  `make tun-demo` ile doğrulanır.
- **NAT simülatörü** — `internal/nat`, tekrarlanabilir yerel test için
  full-cone, adres-kısıtlı ve symmetric davranışları modeller.

## Hızlı başlangıç

**Go 1.26+ gerekir.**

```sh
make demo
```

Tüm yığını simüle edilmiş NAT'lara karşı iki aşamada çalıştırır:

1. **full-cone** çifti → delik delme başarılı olur, ping'ler `path=direct` bildirir;
2. **symmetric** çifti → doğrudan delme başarısız olur, relay devreye girer ve
   ping'ler uçtan uca yine başarılıdır (`path=relay`).

## Manuel çalıştırma

Adım 1 — servisleri derleyin ve başlatın:

```sh
make build
bin/coordinator -ctrl 127.0.0.1:19200 -stun 127.0.0.1:19201 -keyfile coord.key
# ilk başlatmadaki "control public key ...: <hex>" satırını not edin
bin/relay -addr 127.0.0.1:19205
```

Adım 2 — NAT'ları simüle edin:

```sh
bin/natbox -name nat1 -behavior fullcone -public 127.0.0.1:19301 -door 127.0.0.1:19401 -host 127.0.0.1:19501
bin/natbox -name nat2 -behavior fullcone -public 127.0.0.1:19302 -door 127.0.0.1:19402 -host 127.0.0.1:19502
```

Adım 3 — ajanlar (her biri koordinatör günlüğündeki `--coord-pubkey <hex>` değerini gerektirir):

```sh
bin/agent up --name a --keyfile key.a --data 127.0.0.1:19501 --nat 127.0.0.1:19401 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205

bin/agent ping --name b --keyfile key.b --data 127.0.0.1:19502 --nat 127.0.0.1:19402 \
  --coordinator 127.0.0.1:19200 --coord-pubkey <hex> \
  --stun 127.0.0.1:19201 --relay 127.0.0.1:19205 \
  --peer a --count 3
```

`--relay ""` relay'i devre dışı bırakır (tamamen doğrudan yollar); `--nat ""`
NAT kutularını atlar (doğrudan erişilebilir soketler). Yolda NAT yokken veri
soketi `0.0.0.0`'a bağlanmalıdır (`--data 0.0.0.0:19501`) ki STUN gerçek bir
kaynak adresi görsün — bkz. `docs/tr/TUN.md` / `docs/tr/REALNET.md`.

## Testler

```sh
make test          # go test -race ./internal/...
make fuzz-smoke    # 10s parser fuzz per package (record, relay, nat, stun, protocol)
make demo          # simulated-NAT end-to-end demo (no root)
make tun-demo      # real TUN end-to-end on macOS/Linux (root; re-execs via sudo)
```

### Telde kayıp ölçümü (yeniden iletim)

Dosya hash'leri eşleştiğinde transfer "kayıpsız" görünebilir, ama TCP yığını
telde yine de yeniden iletim yapıyor olabilir. Bunu çıkarım yapmak yerine
doğrudan ölçmek için transferi N kez yakalayıp TCP yeniden-iletim analiz
olaylarını sayın:

```sh
RETX_IFACE=en0 \
  RETX_RUNS=10 \
  RETX_TRANSFER='curl -sfS -o /dev/null https://host/a.bin' \
  scripts/retx-check.sh
```

Her koşu için bir satır basar (`wall`/`cap` süresi, `MB`, `retx`/`fast`/`spur`/
`dup`/`ooo`/`lost` sayaçları, ortalama ACK RTT) ve yalnızca paketlerin
**hiçbirinde** yeniden iletim/sıralama/kayıp belirtisi yoksa `0` ile çıkar —
tel düzeyinde temiz sonuç, çıkarım değil. `RETX_CAP_FILTER` yakalamayı transfer
uç noktalarına daraltır. Mevcut yakalamalar
`scripts/retx-check.sh --analyze <dir>` ile yeniden analiz edilebilir
(yakalama `tcpdump`'a düşebilir; analiz için `tshark` gerekir). Gerçek bir
arayüzde yakalama root ister:
`sudo env RETX_IFACE=en0 RETX_TRANSFER='curl -sfS -o /dev/null https://host/a.bin' scripts/retx-check.sh`.

CI, `main` dalına her push'ta `gofmt` → `go vet` → `go test -race ./...` → `make demo`
çalıştırır:

[![CI](https://github.com/firfircelik/network-project/actions/workflows/ci.yml/badge.svg)](https://github.com/firfircelik/network-project/actions/workflows/ci.yml)

## Dokümantasyon

| Doküman | İçerik |
|---|---|
| [`docs/tr/ARCHITECTURE.md`](docs/tr/ARCHITECTURE.md) | bileşenler, veri düzlemi, yol seçimi, NAT modeli |
| [`docs/tr/SPEC.md`](docs/tr/SPEC.md) | hat formatları ve paket düzeyi sözleşmeler |
| [`docs/tr/THREAT_MODEL.md`](docs/tr/THREAT_MODEL.md) | tehdit modeli, azaltıcı önlemler, açık boşluklar |
| [`docs/tr/ROADMAP.md`](docs/tr/ROADMAP.md) | uygulama aşamaları ve durum |
| [`docs/tr/TUN.md`](docs/tr/TUN.md) | TUN köprüsü — macOS, Linux, makineler arası |
| [`docs/tr/REALNET.md`](docs/tr/REALNET.md) | gerçek internet doğrulama tarifi (VPS) |
| [`docs/tr/REVIEW.md`](docs/tr/REVIEW.md) | kod inceleme günlüğü |

## Durum

Faz 1 (CI, fuzz, yapılandırma/günlük hijyeni) ve Faz 2 (tekrar penceresi, rekey,
nonce korumaları) tamamlandı; Faz 3 (kimliği doğrulanmış kontrol düzlemi, relay
sabitleme + hız limitleri, el sıkışma bütçeleri) tamamlandı; Faz 4 (TUN köprüsü)
uygulandı ve dokümante edildi — kalan tek madde gerçek internet üzerinde
doğrulamadır (bkz. `docs/tr/REALNET.md`).
