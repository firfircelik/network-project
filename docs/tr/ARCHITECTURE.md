# meshlink — Mimari

`meshlink`, Go ile yazılmış mini bir sıfır-güven (zero-trust) mesh VPN'dir:
şifreli bir taşıma katmanı, NAT aşımı, taşıma düşüşü ve modüler bir istemci.
Geliştirme sırasında tamamen localhost üzerinde çalışır — NAT kutuları simüle
edildiği için delik delme ve relay düşüşü root veya gerçek ağ donanımı olmadan
gösterilebilir.

## Bileşenler

```
                    ┌──────────────────────────┐
                    │ coordinator (TCP)        │  control plane:
                    │   peer registry          │  register + broadcast peer
                    │   (UDP) STUN endpoint    │  lists; NAT endpoint discovery
                    └──────────┬───────────────┘
                       TCP/JSON│
            ┌──────────────────┴──────────────────┐
            │                                     │
   ┌────── natbox1 (NAT sim) ──┐        ┌── natbox2 (NAT sim) ─┐
   │ public 127.0.0.1:19301    │        │ public 127.0.0.1:19302│
   │ door   127.0.0.1:19401    │        │ door   127.0.0.1:19402│
   └───────┬───────────────────┘        └───────┬───────────────┘
           │ dataplane (Noise/UDP)              │
        agent a                              agent b
    (127.0.0.1:19501)                    (127.0.0.1:19502)
            └─────────────── relay (UDP 127.0.0.1:19205) ───────┘
```

## Veri düzlemi

- Her UDP datagram'ı tek bir *çerçevedir*: `[1B type][2B length][payload]`
  (bkz. `internal/record`).
- Şifreleme: Noise Protocol Framework, **XX deseni**,
  `DH25519 + ChaCha20-Poly1305 + SHA256`, prolog `meshlink-v1`
  (bkz. `internal/noisework`).
- Kimlik: her ajan kalıcı bir X25519 anahtar çifti tutar. Koordinatör genel
  anahtarları dağıtır; XX el sıkışmasından sonra her iki taraf da eşin statik
  anahtarını koordinatörde kayıtlı anahtara karşı **doğrular**. Relay asla
  düz metin görmez — şifreleme uçtan ucadır.
- Roller: sözlükbilimsel olarak daha küçük ajan kimliği el sıkışma
  başlatıcısıdır; böylece iki taraf ek sinyalleşme olmadan anlaşır
  (`internal/disco`).

## Yol seçimi

1. **Doğrudan (P2P):** her iki taraf da NAT eşlemelerini açmak için diğerinin
   ilan edilen uç noktasına doğru yoklama (`type=4`) gönderir, ardından Noise
   el sıkışmasını çalıştırır.
2. **Relay düşüşü:** doğrudan el sıkışma `disco.DirectAttempt` içinde
   tamamlanamazsa trafik relay'e geçer: çerçeveler
   `[magic 0x52][src][dst][frame]` olarak sarılır; relay ciphertext'i eş
   kimliğine göre iletir (`internal/relay`).
3. **Geri dönme:** relay üzerinde kuruluyken ajan doğrudan yolu yeniden
   yoklamaya devam eder (`disco.ReestablishInterval`) ve mümkün olduğunda P2P
   üzerinden yeniden el sıkışır.

## NAT simülasyonu (`internal/nat`, `cmd/natbox`)

Bir natbox'ın bir *public* soketi (dış dünyanın görünümü) ve bir *iç kapısı*
(inside door) vardır. Arkasındaki ajanlar kapı üzerinden çıkış yapar
(`[dst][payload]` sarmalayıcısı). Davranışlar:

- `fullcone`    — iç host başına tek eşleme; herhangi bir kaynaktan gelen giriş
  (inbound) kabul edilir.
- `restricted`  — yalnızca daha önce temas edilen IP'lerden gelen giriş kabul edilir.
- `symmetric`   — **her hedef için taze bir public port**; giriş yalnızca eşin
  bize ulaşmak için kullandığı eşlemenin tamamında kabul edilir. Klasik
  eşzamanlı açılış delik delmeyi başarısız kılan ve relay'i gösteren şey budur.

## Kontrol düzlemi (`internal/protocol`, `internal/coordinator`)

Ajanlar `coordinator`'ı (TCP) arar, `register {id, pubkey, endpoints}` gönderir
ve kayıtlı tüm eşleri içeren `peer_list` yayınlarını alır. İlk uç nokta STUN ile
öğrenilen public adrestir; ikincisi (isteğe bağlı) relay'dir. Yeniden kayıt uç
nokta eşlemelerini günceller. Koordinatör ayrıca bir UDP portunda STUN binding
isteklerini yanıtlar.

## Ping / canlılık

Kurulmuş bir oturum Noise üzerinden JSON mesajları taşır:
`{"cmd":"ping","s":seq,"ts":nanos}` → `{"cmd":"pong","s":seq,"ts":nanos}`.
Ping gönderen RTT, kayıp ve etkin yolu (`direct|relay`) raporlar.

## Bilinen sınırlamalar (MVP)

- Kontrol düzlemi Noise XX ile kimlik doğrular ve koordinatörün statik anahtarını
  sabitler, ancak TLS sertifika hikâyesi yoktur; operatör güveni bant dışıdır
  (anahtar dağıtımı).
- Oturumlar relay→direct arasında gezer ama oturum ortasında direct→relay geçişi
  yapmaz.
- Overlay adresleri statik olarak atanır (`-tun-peer`); henüz dinamik adres
  tahsisi yoktur.
- TUN desteği mevcuttur (`internal/tun`, `internal/agent/tunbridge.go`) ancak
  root gerektirir ve `make demo` tarafından çalıştırılmaz; gerçek internet NAT
  doğrulaması (simülatörün ötesinde) açık bir Faz 4 maddesidir.

## Dizin genel bakış

```
cmd/{coordinator,relay,natbox,agent}   thin binaries
internal/record      frame codec
internal/noisework   Noise XX handshake + session (rekey, replay window)
internal/control     authenticated control connection + framing
internal/stun        RFC 8489 binding client/server
internal/nat         NAT simulator
internal/relay       UDP relay server (name pinning, rate limits)
internal/protocol    control-plane JSON
internal/coordinator control-plane server (Noise-auth, key pinning)
internal/disco       punching policy (timing, roles, path enum)
internal/peer        per-peer session state machine
internal/agent       client glue (keys, STUN, register, receive loop)
internal/tun         TUN device + IPv4 route table (Faz 4)
```
