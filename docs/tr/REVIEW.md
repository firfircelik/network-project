# meshlink — Kod İnceleme Raporu

Tarih: 2026-08-19 · Kapsam: tüm kaynak, testler, dokümantasyon, Makefile, demo betiği.
Yöntem: 5 eksenli inceleme + `gofmt` / `go vet` / `go test -race` / `make demo`
ile canlı doğrulama.

---

## Durum

| Madde | Önem | Durum |
|---|---|---|
| H1 — `Peer.Run` `p.done`'ı izlemiyordu → goroutine sızıntısı | Yüksek | ✅ Düzeltildi + regresyon testi |
| H2 — Kısıtlı NAT `contactIP` birikmiyordu | Yüksek | ✅ Düzeltildi + çok hedefli test |
| H3 — Koordinatör ID→pubkey sabitlemesi yoktu | Orta/güvenlik | ✅ Düzeltildi + test |
| M1 — Relay kaynak ismi doğrulanmıyordu | Orta/güvenlik | ✅ Düzeltildi (Faz 3: isim→adres sabitleme) + test |
| M2 — `MaxPlaintextLen` UDP limitini aşıyordu | Orta | ✅ Düzeltildi (65504; relay yolu daha da daraltıldı) |
| M3 — `scripts/demo.sh` çalıştırılabilir değildi | Orta | ✅ `chmod +x` |
| M4 — README bayat natbox bayrakları | Orta | ✅ Güncellendi |
| M5 — `disco.MaxPunchAttempts` ölü sabit + SPEC "max 10" | Orta | ✅ Kaldırıldı / dokümante edildi |
| D1 — nat `wg.Add`/`Wait` eşzamanlılığı | Düşük | ✅ `closed` koruması |
| D2 — Ping özeti yolu çalıştırma başında yakalanıyordu | Düşük | ✅ Çalıştırma sonunda okunuyor |
| D3 — Kontrol bağlantısında yazma zaman aşımı yok | Düşük | ✅ `broadcastWriteDeadline` + yazma mutex'i |
| D4 — Ping gönderme hatası yutuluyordu | Düşük | ✅ Günlüğe yazıldı |
| D5 — JSON kod çözme hatası sessizdi | Düşük | ✅ Günlüğe yazıldı |
| D6 — `nat.decodeOutbound` test takozu üretimde | Düşük | ✅ Test dosyasına taşındı |
| D7 — `go.mod` `// indirect` yorumları | Düşük | ✅ `go mod tidy` |
| D8 — `receiveLoop` her pakette kopyalama | Düşük | ✅ Yalnızca eşleşen çerçeve kopyalanıyor |
| Bonus | — | ✅ Ölü `peer.maxPlaintext()` kaldırıldı |

## Doğrulama

```
gofmt -l .                → boş
go vet ./...              → temiz
go build ./...            → ok
go test -count=1 -race ./... → tümü ok (control/coordinator/peer/nat/agent/tun yeni testler dahil)
make demo                 → phase 1 path=direct PASS · phase 2 path=relay PASS
```

---

## Önceki Oturum Bulguları ve Çözüm Ayrıntıları

### H1 — `Peer.Run` `p.done`'ı izlemiyor (goroutine sızıntısı)
`internal/peer/peer.go` — `Run` yalnızca `ctx.Done()` üzerinde bekliyordu;
`Close()` tarafından kapatılan `p.done` döngüde izlenmiyordu ve `p.recv` hiç
kapanmıyordu (iki goroutine `applyPeers` budamasını sonsuza dek sızdırıyordu).
Düzeltme:

- `p.done` artık `doneOnce sync.Once` ile tam olarak bir kez kapanıyor.
- `Run`'ın defer'i `recv`'i kilit altında kapatıyor (eşzamanlı gönderme yarışı yok).
- `onData` kilit altında korumalı (`closed`/`recvClosed`), engellemesiz bir gönderim yapıyor.
- Regresyon testi: `internal/peer/peer_test.go` (`TestRunExitsWhenClosed`,
  `TestRunExitsOnCancel`, `TestNoDataAfterClose`).

### H2 — Kısıtlı NAT `contactIP` birikimi
`internal/nat/nat.go` — eşleme-yenileme dalında `e.contactIP[ipKey(dst.IP)] = true`
eksikti; host, daha sonra temas ettiği IP'lerden gelen giriş trafiğini
yanlışlıkla DROP'luyordu. Regresyon testi:
`internal/nat/nat_test.go` → `TestAddressRestrictedMultiTarget`.

### H3 — Koordinatör anahtar sabitlemesi
`internal/coordinator/coordinator.go` — Aynı ID ile farklı bir `PubKey`
TypeError yükseltir (kayıt üzerine yazılmaz); boş bir pubkey reddedilir; aynı
anahtarla yeniden kayıt (uç nokta yenileme) serbest kalır.
Regresyon testi: `TestRegistrationKeyPinning`.

### M2 — Datagram boyut sözleşmesi
- `internal/noisework/noisework.go`: `maxPlaintextLen = 65507 - 3 - 16 = 65504`
  (25535 − IP(20) − UDP(8) headers; frame hdr 3; AEAD tag 16).
- `internal/relay/relay.go`: `MaxHeaderLen` dışa aktarıldı (en kötü durum 133 B).
- `internal/peer/peer.go`: relay yolundaki `Send` limiti `MaxPlaintextLen - MaxHeaderLen`.
- Test/SPEC/noisework_test uyarlandı; `record`'un 65535 kodlama sözleşmesi (tek
  bir paket değil, codec limiti) korundu.

### D8 — `receiveLoop` bellek tahsisi azaltımı
`internal/agent/agent.go` — Özel bir çerçeve kopyası yalnızca eşleşen çerçeve
için yapılır; eşleşmeyen (boşta düşürülen) datagram'lar paylaşılan tampondan
kopyalanmadan atılır. Relay demux hâlâ eş kimliğine göredir.

---

## Faz 3/4 Oturumu Ek Bulgular

### D9 — Eşzamanlı kontrol yazıcıları çerçeveleri bozabiliyordu (Yüksek)
`internal/control` — İki `handleClient` örneği aynı istemci `*control.Conn`'una
eşzamanlı yazabiliyordu (yayın + kişisel yanıt); `WriteMsg` iki ayrı `Write`
çağrısı yaptığından (uzunluk başlığı + ciphertext), `-race` altında çerçeveleme
bozulabiliyordu. Düzeltme: `Conn.wm sync.Mutex` + atomik tek-tampon yazım.
`TestRegistrationAndBroadcast` sıralama açısından belirlenimci hale getirildi.

### D10 — Kontrol el sıkışmasının zaman aşımı yoktu (Orta)
`internal/control` — `Initiate`/`Accept` bir `handshakeTimeout` ile sınırlı
olmadığından takılan eşler kabul ediciyi kilitleyebiliyordu. Düzeltme:
girişte `SetDeadline(handshakeTimeout)`, başarıdan sonra temizlenir.
`TestWrongCoordinatorKey` artık istemci tarafında belirlenimci biçimde döner.

### Y1 — TUN köprüsü (Faz 4 / G6, kısmi)
`internal/tun` (utun/TUN açma, `Router` IPv4 iletme, `BufferDevice`) +
`internal/agent/tunbridge.go` (cihaz ⇄ eş oturumu köprüsü, `-tun`/`-tun-ip`/
`-tun-peer`). Rootsuz birim testleri: `internal/tun/tun_test.go`,
`internal/agent/tunbridge_test.go`. Gerçek cihaz açma testlerde `t.Skip`
ile atlanır; gerçek ağ doğrulaması bir Faz 4 kalıntısıdır (docs/tr/TUN.md).

---

## Test Kapsamı Değerlendirmesi

Mevcut: record, noisework, stun, nat, relay, coordinator, protocol, peer,
control, tun, agent (tun köprüsü) — çok iyi. Fuzz'lar: record, relay, nat,
stun, protocol. Açık (v1.1): gerçek internet NAT doğrulaması; canlı uçtan uca TUN
yaşam döngüsü (root gerektirir).

## Kapanış

Rapordaki uygulanabilir tüm maddeler çözüldü ve doğrulama üç katmanda yapıldı
(birim test `-race`, `go vet`/`gofmt`, uçtan uca `make demo`). M1
(relay tarafı kimlik doğrulaması) Faz 3'te kapatıldı; gerçek ağ testleri
bilinçli olarak Faz 4 kalıntısı olarak bırakıldı.