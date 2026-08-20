# meshlink — Tehdit Modeli (v0.x → v1.0)

Tarih: 2026-08-19
Bu belge MVP'den üretim gerçekçiliğine geçişin temel taşıdır. Mevcut kod bir
**demo/MVP'dir**; bu model hangi kontrollerin eksik olduğunu açıkça listeler.

---

## 1. Kapsam ve Varlıklar

Sistem dört bileşenden oluşur: **agent** (istemci), **coordinator** (kontrol
düzlemi: kayıt + STUN), **relay** (veri düzlemi taşıması) ve isteğe bağlı
**TUN köprüsü** (gerçek IP veri taşıması, root gerektirir). Demo ayrıca gerçek
NAT cihazlarını taklit eden **natbox**'ı da içerir — üretimde bulunmaz.

Varlıklar:

| Varlık | Gizlilik | Bütünlük | Kullanılabilirlik |
|---|---|---|---|
| Ajan X25519 statik anahtarı | Yüksek | Yüksek | — |
| Oturum verisi (uçtan uca düz metin) | Yüksek | Yüksek | Orta |
| Koordinatör kayıt defteri (isim→anahtar, uç nokta) | Orta | Yüksek | Yüksek |
| Relay mesaj akışı | Orta (yön/kimlik metaverisi) | Yüksek | Yüksek |
| STUN yanıtları (XOR-MAPPED-ADDRESS) | Düşük | Yüksek | Düşük |

## 2. Güven Sınırları

```
 [güvenilir]                   [yarı güvenilir / ağa düşman]          [güvenilir]
 agent A ──coord/STUN──▶ coordinator ◀──coord/STUN── agent B
     │                                                            │
     └─────Noise (E2E)──▶ relay (ciphertext only) ◀──Noise──────┘
```

- **Agent çekirdeği** tamamen güvenilirdir; **coordinator ve relay** "ağa açık,
  taşıma kutsal"dır (veriyi göremezler çünkü Noise uçtan ucadır).
- **Ağ yolu** (internet/NAT'lar) tamamen düşmanca kabul edilir.
- **natbox** bir demo artefaktıdır; etrafında üretim güven sınırı çizilmez.
- Kontrol kanalı artık Noise ile kimliği doğrulanır; koordinatörün gerçekliği
  istemcide sabitlenmiş bir anahtar üzerinden doğrulanır (Faz 3).

## 3. Tehditler (STRIDE)

### 3.1 T1 — Ayrıcalıksız ağ saldırganı (veri yolu)
- **Tekrar (Replay):** kaydedilmiş DATA ciphertext'inin yeniden iletilmesi.
  Alıcıdaki WireGuard tarzı kayan pencere (2048) eski nonce'ları ve yinelenenleri
  reddeder → **azaltıldı** (Faz 2).
- **UDP DoS/yansıma (reflection):** relay'e bir isim sahiplenerek amplifikasyon;
  sahte kaynak adresli paketler. İsim→adres sabitleme + kaynak başına pps/byte
  limitleri + isim başına kota etkindir → **azaltıldı** (Faz 3).
- **El sıkışma seli:** HS1 üzerinden CPU tüketimi (her istek yeni el sıkışma
  durumu oluşturur). Yanıtlayıcının eşzamanlı el sıkışma bütçesi + el sıkışma
  zaman aşımı vardır → **azaltıldı** (Faz 3).
- **STUN sahteciliği:** yanlış bir uç nokta enjekte etme — txid doğrulaması vardır
  ve anahtar doğrulaması oturumu kurtarır → **azaltıldı**.

### 3.2 T2 — Haydut ajan (kayıt olabilen kötü niyetli istemci)
- **İsim ele geçirme:** meşru "a"dan önce "a" ismini kaydedip ping'i engelleme.
  Koordinatörde anahtar sabitleme + kimlik/anahtar uyuşmazlığının reddi →
  **azaltıldı** (Faz 3).
- **Sahte relay iddiası:** relay'e başkasının srcID'siyle paket gönderme.
  İsim→adres sabitleme bunu önler → **azaltıldı** (Faz 3, eski M1 kapanır).
- **Sahte uç noktayla yanlış yönlendirme:** koordinatörü kötü bir uç noktayla
  doldurma; diğer ajanlar el sıkışma sırasında anahtarı doğrular ama yanlış adresi
  yoklar → **kısmen azaltıldı** (kontrol kanalı Noise ile kimliği doğrulanır,
  kayıt değişiklikleri şifresiz ağ üzerinde artık mümkün değildir).

### 3.3 T3 — Koordinatör / relay operatörü saldırganı
- Kontrol kanalı şifresiz/TLS'sizdi → Noise ile kimliği doğrulanmış kontrol
  kanalı + koordinatör pubkey sabitleme ile kapatıldı → **azaltıldı** (Faz 3).
- Relay isim→adres tablosunu tutar; bir operatör bir aboneyi değiştirebilir veya
  akışı gözlemleyebilir (metaveri: kim kiminle hangi saatte konuşuyor). Uçtan uca
  Noise bunu çözmez; metaveri gizliliği ayrı bir gereksinimdir → **belgelenmiş kabul**.

### 3.4 T4 — Yerel işletim
- Anahtar dosyası: `0600` izinleri **iyidir**; ancak düz metin özel anahtar →
  disk şifreleme/KMS bir üretim gereksinimidir.
- Bellek dökümü / core dump içinde anahtar + düz metin → üretimde mlock/koruma
  düşünülmelidir (v1 sonrası).

## 4. Mevcut Azaltıcı Önlemler (uygulanmış)

- Noise XX + DH25519 + ChaCha20-Poly1305 + SHA256; çift yönlü statik anahtar
  doğrulaması (koordinatör tarafından dağıtılan pubkey ile, isteğe bağlı).
- Anahtar sabitleme: koordinatör aynı isim + farklı bir anahtarla bir kaydı
  reddeder; relay isim→adres sabitlemesi teslimat bozmayı önler.
- Noise ile kimliği doğrulanmış kontrol kanalı: kayıt/kontrol trafiği şifrelidir
  ve değiştirilemez.
- Veri düzlemi: kayan pencere (2048) tekrar reddi, periyodik rekey, nonce tükenme
  koruması + `maxEpochJump` DoS kapağı, oturum yaş sınırı.
- Relay rate-limit/kota (kaynak başına pps/byte, isim başına kota); el sıkışma
  bütçesi + zaman aşımı (relay ve kontrol).
- STUN txid doğrulaması.
- İletişimde boyut limitleri (kontrol `maxMsgLen`, relay/nat zarfı), çerçeve
  geçerlilik kontrolü.
- Datagram boyut sözleşmesi (65507-3-16 düz metin tavanı, relay yolu ek olarak
  sıkılaştırılmıştır).
- Koordinatör yayın yazma zaman aşımı; sınırlı kontrol okumaları.
- `-race`-temiz birim testleri; ayrıştırıcı fuzz'ları; uçtan uca demo; CI iş akışı.

## 5. Bilinen Boşluklar (üretim engelleyicileri)

| # | Boşluk | Etki | Durum |
|---|---|---|---|
| G1 | — (tekrar penceresi + rekey) | — | ✅ Faz 2 |
| G2 | — (relay isim sabitleme) | — | ✅ Faz 3 |
| G3 | — (kontrol Noise-auth) | — | ✅ Faz 3 |
| G4 | — (relay rate-limit/kota) | — | ✅ Faz 3 |
| G5 | — (el sıkışma bütçesi/zaman aşımı) | — | ✅ Faz 3 |
| G6 | TUN yaşam döngüsü + gerçek ağ doğrulaması | VPN kullanımı için gerçek ağ NAT testi açık | 🔶 Faz 4 kısmi |
| G7 | — (fuzz, CI, sağlık günlükleri) | — | ✅ Faz 1 |
| G8 | — (rekey, tekrar penceresi) | — | ✅ Faz 2 |
| G9 | Ortam değişkeni yapılandırması; metrikler/Prometheus | Operasyonel öngörülebilirlik | 🔶 v1.1+ |

## 6. Kabul Edilen Riskler (MVP)

- **Kontrol düzlemi metaveri güveni:** koordinatör/relay operatörünün "kim kiminle
  ne zaman konuşuyor" bilgisini görmesi, uçtan uca şifrelemeye rağmen kabul edilir.
- **Paralellik / DTLS:** UDP veri düzlemi DTLS kullanmaz; enerji/metaveri analizi
  teorik olarak mümkündür (WireGuard modeli kabulü).
- **natbox simülasyonu** gerçek internet NAT'larının çeşitliliğini kapsamaz
  (Cone/Cone, operatör sınıfı vb.); gerçek ağ testi bir Faz 4 artığıdır.

## 7. Kapanış Kontrolleri (yol haritası eşlemesi)

Faz 1 → G7, G9; Faz 2 → G1, G8; Faz 3 → G2–G5; Faz 4 → G6.
Her fazın sonunda testler + dokümantasyon güncellenir; bu tablo da güncellenir.
