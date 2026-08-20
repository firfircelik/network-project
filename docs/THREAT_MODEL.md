# meshlink — Tehdit Modeli (v0.x → v1.0)

Tarih: 2026-08-19
Doküman, MVP'den production gerçekçiliğine geçişin temel taşıdır. Mevcut kod bir
**demo/MVP'dir**; bu model, hangi kontrollerin eksik olduğunu açıkça listeler.

---

## 1. Kapsam ve Varlıklar

Sistem dört bileşenden oluşur: **agent** (istemci), **coordinator** (kontrol
düzlemi: kayıt + STUN), **relay** (veri düzlemi aktarımı) ve isteğe bağlı
**TUN köprüsü** (gerçek IP veri taşıma, root gerektirir). Demo ayrıca gerçek
NAT cihazlarını taklit eden **natbox** içerir — production'da yoktur.

Varlıklar:

| Varlık | Gizlilik | Bütünlük | Kullanılabilirlik |
|---|---|---|---|
| Agent X25519 statik anahtarı | Yüksek | Yüksek | — |
| Oturum verileri (uçtan uca plaintext) | Yüksek | Yüksek | Orta |
| Koordinatör kayıt defteri (isim→anahtar, endpoint) | Orta | Yüksek | Yüksek |
| Relay ileti akışı | Orta (yön/kimlik metadata) | Yüksek | Yüksek |
| STUN yanıtları (XOR-MAPPED-ADDRESS) | Düşük | Yüksek | Düşük |

## 2. Güven Sınırları

```
 [güvenilir]                   [yarı güvenilir / ağa düşman]          [güvenilir]
 agent A ──coord/STUN──▶ coordinator ◀──coord/STUN── agent B
     │                                                            │
     └─────Noise (E2E)──▶ relay (ciphertext only) ◀──Noise──────┘
```

- **Agent çekirdeği** tam güvenilir; **koordinatör ve relay** "ağa maruz,
  aktarım kutsal" (Noise E2E olduğu için veriyi göremezler).
- **Ağ yolu** (internet/NAT'lar) tamamen düşman kabul edilir.
- **natbox** demo artefaktıdır; production güven sınırı çizilmez.
- Kontrol kanalı artık Noise-auth'ludur; koordinatörün gerçekliği istemcide
  sabitlenmiş anahtar üzerinden doğrulanır (Faz 3).

## 3. Tehditler (STRIDE)

### 3.1 T1 — İmtiyazsız ağ saldırganı (veri hattı)
- **Replay:** kaydedilen DATA ciphertext'inin yeniden iletimi. Alıcıdaki
  WireGuard tarzı kayar pencere (2048) eski nonce'ları ve tekrarları reddeder
  → **azaltılmış** (Faz 2).
- **UDP DoS/reflection:** relay'e isim iddia ederek amplification; kaynak
  adresi sahte paketler. İsim→adres pinleme + kaynak-başına pps/byte limiti +
  isim başına kota aktiftir → **azaltılmış** (Faz 3).
- **Handshake flood:** HS1 ile CPU tüketimi (her istek yeni handshake durumu).
  Responder'da eşzamanlı handshake budget'ı + handshake timeout'u vardır →
  **azaltılmış** (Faz 3).
- **STUN sahteleme:** yanlış endpoint enjekte etme — txid doğrulaması var ve
  key verifikasyonu oturumu kurtarır → **azaltılmış**.

### 3.2 T2 — Rogue agent (kayıt olabilen kötü niyetli istemci)
- **İsim kaçırma:** meşru "a"dan önce "a" adıyla kayıt olup ping'i engelleme.
  Anahtar pinleme + koordinatörde kimlik/anahtar uyuşmazlığı reddi →
  **azaltılmış** (Faz 3).
- **Sahte relay iddiası:** relay'e başkasının srcID'si ile paket gönderme.
  İsim→adres pinleme bunu engeller → **azaltılmış** (Faz 3, eski M1 kapanır).
- **Dolu endpoint ile yanlış yönlendirme:** koordinatörü kötü endpoint ile
  spam'leme; diğer agent'lar handshake'te anahtarı doğrular ama yanlış adrese
  probe atar → **kısmi azaltılmış** (kontrol kanalı Noise-auth'ludur, kayıt
  değişimi artık şifresiz ağda mümkün değildir).

### 3.3 T3 — Koordinatör / relay operator saldırganı
- Kontrol kanalı şifresiz/TLS'sizdi → Noise-auth'lı kontrol kanalı +
  koordinatör pubkey sabitleme ile kapatıldı → **azaltılmış** (Faz 3).
- Relay, isim→adres tablosunu tutar; bir operator aboneyi değiştirebilir veya
  akışı izleyebilir (metadata: kim kime hangi saatte). E2E Noise bunu düzeltmez;
  metadata gizliliği ayrı bir gereksinimdir → **belgeli kabul**.

### 3.4 T4 — Yerel işletim
- Anahtar dosyası: `0600` perms **iyi**; ancak düz metin privkey → disk
  şifreleme/KMS production gereksinimi.
- Memory dump / core dump'ta anahtar + plaintext → production'da mlock/guard
  düşünülmeli (v1 sonrası).

## 4. Mevcut Azaltımlar (yapılmış)

- Noise XX + DH25519 + ChaCha20-Poly1305 + SHA256; iki taraflı statik anahtar
  doğrulaması (koordinatör dağıtımlı pubkey ile, opsiyonel).
- Anahtar pinleme: koordinatör aynı isim+farklı anahtar kaydını reddeder;
  relay isim→adres pinlemesi teslimat bozmayı engeller.
- Kontrol kanalı Noise-auth: kayıt/denetim trafiği şifreli, el değiştirilemez.
- Veri düzlemi: kayar pencere (2048) replay reddi, periyodik rekey, nonce
  tükenme guard'ı + `maxEpochJump` DoS kapağı, oturum yaş sınırı.
- Relay rate-limit/kota (kaynak başına pps/byte, isim başına kota);
  handshake budget + timeout (relay ve kontrol).
- STUN txid doğrulaması.
- İletişimde boyut limitleri (kontrol `maxMsgLen`, relay/nat zarfı), frame
  geçerlilik denetimi.
- Datagram boyut sözleşmesi (65507-3-16 plaintext tavanı, relay yolu ayrıca
  daraltılır).
- Koordinatör broadcast write deadline; sınırlı kontrol okuma.
- `-race` temiz birim testleri; parser fuzz'ları; uçtan uca demo; CI workflow.

## 5. Bilinen Açıklar (production engelleri)

| # | Açık | Etki | Durum |
|---|---|---|---|
| G1 | — (replay pencere + rekey) | — | ✅ Faz 2 |
| G2 | — (relay isim pinleme) | — | ✅ Faz 3 |
| G3 | — (kontrol Noise-auth) | — | ✅ Faz 3 |
| G4 | — (relay rate-limit/kota) | — | ✅ Faz 3 |
| G5 | — (handshake budget/timeout) | — | ✅ Faz 3 |
| G6 | TUN yaşam döngüsü + gerçek ağ doğrulaması | VPN kullanımı için gerçek ağ NAT testi açık | 🔶 Faz 4 kısmi |
| G7 | — (fuzz, CI, sağlık logları) | — | ✅ Faz 1 |
| G8 | — (rekey, replay pencere) | — | ✅ Faz 2 |
| G9 | Ortam değişkeni config; metrik/Prometheus | Operasyonel tahmin edilebilirlik | 🔶 v1.1+ |

## 6. Kabul Edilen Riskler (MVP)

- **Kontrol düzlemi metadata güveni:** koordinatör/relay operatorunun
  "kim kime ne zaman" bilgisini görmesi, E2E şifrelemeye rağmen kabul edilir.
- **Koşutluk / DTLS:** UDP veri düzlemi DTLS kullanmaz; enerji/metadata
  analizi teorik olarak mümkündür (WireGuard modeli kabulü).
- **natbox simülasyonu** gerçek internet NAT çeşitliliğini (Cone/Cone,
  carrier-grade vs.) göstermez; gerçek ağ testi Faz 4 kalıntısıdır.

## 7. Kapama Kontrolleri (roadmap eşlemesi)

Faz 1 → G7, G9; Faz 2 → G1, G8; Faz 3 → G2–G5; Faz 4 → G6.
Her faz sonunda test + dokümantasyon güncellenir; bu tablo da güncellenir.