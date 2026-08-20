# meshlink — Üretim Yol Haritası (v1)

Güncel durum: **Faz 1–3 tamamlandı; Faz 4 kısmi** (TUN kodu + dokümantasyon
hazır; gerçek internet NAT testi açık). Her fazın sonunda `gofmt` / `go vet` /
`go test -race` / `make demo` yeşil tutulur.

## Faz 1 — Güven/Kalite Altyapısı (hedef: G7, G9) — ✅ tamamlandı

- ✅ GitHub Actions CI: `.github/workflows/ci.yml` — `gofmt`, `go vet`,
  `go test -race ./...`, `make demo`.
- ✅ Fuzz testleri: `record`, `relay`, `nat`, `stun`, `protocol` kod çözücüleri
  (düz bozuk girdi, kırpma, uzunluk alanı abartması) + `make fuzz-smoke`.
- ✅ Sınırlı kontrol okumaları: `control.ReadMsg` `maxMsgLen` tavanı, el sıkışma
  uzunlukları 16-bit tavan; bellek DoS yüzeyi kapatıldı.
- ✅ Yapılandırılmış günlükleme: `log/slog` (`level=INFO msg=...`), error/warning/info.
- ✅ Yapılandırma: bayrak doğrulaması (`--name`/`--keyfile`/`--coord-pubkey`
  zorunlu); anahtar dosyası yokken `0600` ile oluşturulur ve izinler korunur.
  (Ortam değişkeni tabanlı yapılandırma → v1.1+.)

## Faz 2 — Tünel Çekirdeği Sertleştirmesi (hedef: G1, G8) — ✅ tamamlandı

- ✅ **Tekrar penceresi + kayıp toleransı:** DATA çerçevelerinde açık 64-bit
  nonce; alıcıda WireGuard tarzı kayan pencere (bitmap, 2048 paket). Çok eski
  kayıtlar/tekrarlar reddedilir; oturum kayıptan sonra kilitlenmez
  (`internal/noisework`, `internal/peer`).
- ✅ **Periyodik rekey:** `RekeyEvery` mesajı bir anahtar dönüşü tetikler; her iki
  yön de aynı limitte, kayıp paketler epoch atlamalarıyla izlenir.
- ✅ Nonce tükenme koruması (`MaxNonce`), `maxEpochJump` DoS kapağı ve oturum
  yaş sınırı.
- ✅ Testler: düşürme, tekrar, sıra dışı geliş, bayat nonce, rekey boşluğu
  (`TestDecryptAtLossReorderAndRekey`, `TestRekeyRotatesKeys`,
  `TestRekeyJumpCapped`).

## Faz 3 — Kontrol + Relay Güvenliği (hedef: G2–G5) — ✅ tamamlandı

- ✅ **Relay isim sabitleme:** bir isme bağlı ağ adresi değişirse, başka bir
  kanaldan sahiplenilemez (isim ele geçirme/teslimat bozma kapatıldı).
- ✅ **Relay rate-limit/kota:** kaynak adres başına pps/byte limiti + isim başına
  kota; amplifikasyon yüzeyi daraltıldı.
- ✅ **El sıkışma/CPU bütçesi + el sıkışma zaman aşımı:** yanıtlayıcı tarafta
  eşzamanlı el sıkışma durum limiti ve açık devralma/sönümleme zaman aşımları
  (relay + kontrol).
- ✅ **Kontrol düzlemi Noise kimlik doğrulaması:** register kanalı Noise XX ile
  şifrelenir ve koordinatör anahtarı istemcide sabitlenir; isim→anahtar bağı
  koordinatör tarafında doğrulanır (kimlik/anahtar uyuşmazlıkları reddedilir).

## Faz 4 — Gerçek Veri Taşıma (TUN) (hedef: G6) — 🔶 kısmi

- ✅ `internal/tun`: utun/TUN arayüzü açma, IPv4 yönlendirme (`Router`), bellek
  içi test cihazı (`BufferDevice`); macOS `utun`, Linux `/dev/net/tun`.
- ✅ Agent→tun köprüsü: `internal/agent/tunbridge.go` — şifreli oturum verisini
  IP paketleri olarak yönlendirme (`-tun`, `-tun-ip`,
  `-tun-peer id=ip`).
- ✅ İşletim sistemi adres yapılandırma adımları (root gerektirir) →
  `docs/tr/TUN.md`.
- ⏸ Gerçek internet NAT testi (simülatörün ötesinde) — açık; gerçek bir ağda
  doğrulama gerektirir.

## Sonraki adımlar (v1.1+)

- Ortam değişkeni tabanlı yapılandırma; gerçek internet NAT doğrulaması (Faz 4 artığı).
- Canlı yapılandırma döndürme; kriptografik anahtar deposu/KMS; Prometheus metrikleri;
  düz metin bellek koruması (mlock); WireGuard benzeri oturum zaman aşımları;
  el sıkışma/çekirdek fonksiyon sağlık durumu.
