# meshlink — Production Yol Haritası (v1)

Mevcut durum: **Faz 1–3 tamamlandı; Faz 4 kısmi** (TUN kodu + dokümantasyon
hazır; gerçek internet NAT testi açık). Faz sonlarında `gofmt` / `go vet` /
`go test -race` / `make demo` yeşil tutulur.

## Faz 1 — Güven/Kalite Altyapısı (hedef: G7, G9) — ✅ tamamlandı

- ✅ GitHub Actions CI: `.github/workflows/ci.yml` — `gofmt`, `go vet`,
  `go test -race ./...`, `make demo`.
- ✅ Fuzz testleri: `record`, `relay`, `nat`, `stun`, `protocol` çözücüleri
  (düz bozuk giriş, truncation, uzunluk alanı abartısı) + `make fuzz-smoke`.
- ✅ Sınırlı kontrol okuma: `control.ReadMsg` `maxMsgLen` tavanı, handshake
  uzunlukları 16-bit tavan; bellek DoS yüzeyi kapatılır.
- ✅ Yapılandırılmış günlük: `log/slog` (`level=INFO msg=...`), hata/uyarı/bilgi.
- ✅ Config: flag doğrulaması (`--name`/`--keyfile`/`--coord-pubkey` zorunlu);
  anahtar dosyası eksikken `0600` oluşturulur ve perms korunur.
  (Ortam değişkeni tabanlı config → v1.1+.)

## Faz 2 — Tünel Çekirdeği Sağlamlaştırma (hedef: G1, G8) — ✅ tamamlandı

- ✅ **Replay penceresi + kayıp toleransı:** DATA frame'lerinde açık 64-bit
  nonce; alıcıda WireGuard tarzı kayar pencere (bitmap, 2048 paket). Çok eski
  kayıtların/tekrarların reddi; kayıp sonrası oturum kilitlenmez
  (`internal/noisework`, `internal/peer`).
- ✅ **Periyodik rekey:** `RekeyEvery` mesajda bir anahtar dönüşü; her iki
  yön aynı sınırda, kayıp paketler epoch atlamalarıyla izlenir.
- ✅ Nonce tükenme guard'ı (`MaxNonce`), `maxEpochJump` DoS kapağı ve oturum
  yaş sınırı.
- ✅ Test: bırakma, tekrar, sırasız geliş, eskimiş nonce, rekey arası boşluk
  (`TestDecryptAtLossReorderAndRekey`, `TestRekeyRotatesKeys`,
  `TestRekeyJumpCapped`).

## Faz 3 — Kontrol + Relay Güvenliği (hedef: G2–G5) — ✅ tamamlandı

- ✅ **Relay isim pinleme:** bir isme bağlı ağ adresi değişirse başka
  kanaldan sahiplenilemez (isim kaçırma/teslimat bozma kapatılır).
- ✅ **Relay rate-limit/kota:** kaynak adresi başına pps/byte limiti + isim
  başına kota; amplification yüzeyi daraltılır.
- ✅ **Handshake/CPU budget + handshake timeout:** responder tarafında
  eşzamanlı handshake durumu sınırı ve açık ele geçme/çürüme zaman aşımı
  (relay + control).
- ✅ **Kontrol düzlemi Noise-auth:** register kanalı Noise XX ile şifrelenir ve
  koordinatör anahtarı istemcide sabitlenir; isim→anahtar bağlama koordinatör
  tarafında doğrulanır (kimlik/anahtar eşleşmesi reddedilir).

## Faz 4 — Gerçek Veri Taşıma (TUN) (hedef: G6) — 🔶 kısmi

- ✅ `internal/tun`: utun/TUN arabirimi açma, IPv4 yönlendirme (`Router`),
  bellekte test aygıtı (`BufferDevice`); macOS `utun`, Linux `/dev/net/tun`.
- ✅ Agent→tun köprüsü: `internal/agent/tunbridge.go` — şifreli oturum
  verilerinin IP paketi olarak yönlendirilmesi (`-tun`, `-tun-ip`,
  `-tun-peer id=ip`).
- ✅ OS adres yapılandırma adımları (root gerektirir) → `docs/TUN.md`.
- ⏸ Gerçek internet NAT testi (simülatörün ötesinde) — açık; gerçek ağda
  doğrulama gerektirir.

## Sonraki adımlar (v1.1+)

- Ortam değişkeni tabanlı config; gerçek internet NAT doğrulaması (Faz 4 kalıntısı).
- Live config rotasyonu; kriptografik anahtar deposu/KMS; Prometheus metrikleri;
  plaintext bellek koruması (mlock); WireGuard benzeri oturum timeout'ları;
  handshake/çekirdek fonksiyon sağlık durumu.