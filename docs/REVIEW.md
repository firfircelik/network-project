# meshlink — Kod İnceleme Raporu

Tarih: 2026-08-19 · Kapsam: tüm kaynak, testler, dokümantasyon, Makefile, demo script.
Yöntem: 5 eksenli inceleme + `gofmt` / `go vet` / `go test -race` / `make demo` canlı doğrulama.

---

## Durum

| Madde | Önem | Durum |
|---|---|---|
| H1 — `Peer.Run` `p.done` izlemiyordu → goroutine sızıntısı | Yüksek | ✅ Çözüldü + regresyon testi |
| H2 — Restricted NAT `contactIP` birikmiyordu | Yüksek | ✅ Çözüldü + çoklu-hedef testi |
| H3 — Koordinatör ID→pubkey pinleme yoktu | Orta/güvenlik | ✅ Çözüldü + test |
| M1 — Relay kaynak adı doğrulamasız | Orta/güvenlik | ✅ Çözüldü (Faz 3: isim→adres pinleme) + test |
| M2 — `MaxPlaintextLen` UDP sınırını aşıyordu | Orta | ✅ Çözüldü (65504; relay yolu ayrıca daraltılır) |
| M3 — `scripts/demo.sh` executable değildi | Orta | ✅ `chmod +x` |
| M4 — README eski natbox flag'leri | Orta | ✅ Güncellendi |
| M5 — `disco.MaxPunchAttempts` ölü sabit + SPEC "max 10" | Orta | ✅ Kaldırıldı / belgelendi |
| D1 — nat `wg.Add`/`Wait` eşzamanlılığı | Düşük | ✅ `closed` guard |
| D2 — Ping özet path'i koşu başında alınıyordu | Düşük | ✅ Koşu sonunda okunuyor |
| D3 — Kontrol conn. write deadline yok | Düşük | ✅ `broadcastWriteDeadline` + write mutex |
| D4 — Ping gönderim hatası gizleniyordu | Düşük | ✅ Loglanıyor |
| D5 — JSON çözme hatası sessizdi | Düşük | ✅ Loglanıyor |
| D6 — `nat.decodeOutbound` üretimdeki test-shim'i | Düşük | ✅ Test dosyasına taşındı |
| D7 — `go.mod` `// indirect` yorumları | Düşük | ✅ `go mod tidy` |
| D8 — `receiveLoop` her pakette kopya | Düşük | ✅ Yalnız eşleşen frame kopyalanıyor |
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

## Önceki Oturum Bulguları ve Çözüm Detayları

### H1 — `Peer.Run` `p.done`'u izlemiyor (goroutine sızıntısı)
`internal/peer/peer.go` — `Run` yalnızca `ctx.Done()` bekliyordu; `Close()` ile
kapatılan `p.done` döngüde izlenmiyordu ve `p.recv` hiç kapanmıyordu (`applyPeers`
prune'u sonsuza dek sızdıran iki goroutine). Çözüm:

- `p.done` artık `doneOnce sync.Once` ile yalnızca bir kez kapanıyor.
- `Run`'ın defer'i `recv`'i kilit altında (eşzamanlı send race olmadan) kapatıyor.
- `onData` kilit altında, `closed`/`recvClosed` guard'lı, seçmeli (non-blocking) send yapıyor.
- Regresyon testi: `internal/peer/peer_test.go` (`TestRunExitsWhenClosed`,
  `TestRunExitsOnCancel`, `TestNoDataAfterClose`).

### H2 — Restricted NAT `contactIP` birikimi
`internal/nat/nat.go` — Mapping refresh dalında
`e.contactIP[ipKey(dst.IP)] = true` eksikti; host sonradan temas ettiği IP'lerden
gelen inbound'u yanlış DROP ediyordu. Regresyon testi:
`internal/nat/nat_test.go` → `TestAddressRestrictedMultiTarget`.

### H3 — Koordinatör anahtar pinleme
`internal/coordinator/coordinator.go` — Aynı ID ile farklı `PubKey` gelirse
TypeError (kayıt ezilmiyor); boş pubkey reddediliyor; aynı anahtarla yeniden
kayıt (endpoint tazeleme) hâlâ serbest. Regresyon testi:
`TestRegistrationKeyPinning`.

### M2 — Datagram boyutu sözleşmesi
- `internal/noisework/noisework.go`: `maxPlaintextLen = 65507 - 3 - 16 = 65504`
  (25535 − IP(20) − UDP(8) başlıkları; frame hdr 3; AEAD tag 16).
- `internal/relay/relay.go`: `MaxHeaderLen` dışa açıldı (en kötü senaryo 133 B).
- `internal/peer/peer.go`: relay yolunda `Send` sınırı `MaxPlaintextLen - MaxHeaderLen`.
- Test/SPEC/noisework_test uyarlaması yapıldı; `record`'un 65535 kodlama
  sözleşmesi (tek paket değil, codec sınırı) korundu.

### D8 — `receiveLoop` tahsis azaltımı
`internal/agent/agent.go` — Ayrılmış frame kopyası yalnızca eşleşen frame için
yapılıyor; eşleşmeyen (boşta atılan) datagramlar paylaşılan tampondan kopyasız
düşürülüyor. Relay demux yine peer ID üzerinden.

---

## Faz 3/4 Oturumu Ek Bulguları

### D9 — Eşzamanlı kontrol yazıcıları frame bozabiliyordu (Yüksek)
`internal/control` — İki `handleClient` aynı istemci `*control.Conn`'una
(broadcast + kişisel yanıt) eşzamanlı yazabiliyordu; `WriteMsg` iki ayrı
`Write` çağrısı (uzunluk başlığı + ciphertext) yaptığından `-race` altında
çerçeveleme bozulabiliyordu. Çözüm: `Conn.wm sync.Mutex` + tek buffer'lık
atomik yazma. `TestRegistrationAndBroadcast` deterministik sıraya alındı.

### D10 — Kontrol handshake timeout'u yoktu (Orta)
`internal/control` — `Initiate`/`Accept` bir `handshakeTimeout` ile
sınırlanmadığı için asılmış akranlar acceptor'ı kilitleyebiliyordu. Çözüm:
`SetDeadline(handshakeTimeout)` girişte, temizlenme başarı sonrası.
`TestWrongCoordinatorKey` artık client tarafında deterministik olarak dönüyor.

### Y1 — TUN köprüsü (Faz 4 / G6, kısmi)
`internal/tun` (utun/TUN açma, `Router` IPv4 yönlendirme, `BufferDevice`) +
`internal/agent/tunbridge.go` (aygıt ⇄ peer oturum köprüsü, `-tun`/`-tun-ip`/
`-tun-peer`). Root'suz birim testler: `internal/tun/tun_test.go`,
`internal/agent/tunbridge_test.go`. Gerçek aygıt açılışı testte `t.Skip` ile
atlanır; gerçek ağ doğrulaması Faz 4 kalıntısıdır (docs/TUN.md).

---

## Test Kapsamı Değerlendirmesi

Mevcut: record, noisework, stun, nat, relay, coordinator, protocol, peer,
control, tun, agent (tun köprüsü) — çok iyi. Fuzz'lar: record, relay, nat,
stun, protocol. Açık (v1.1): gerçek internet NAT doğrulaması; TUN yaşam döngüsü
canlı e2e (root gerektirir).

## Kapanış

Rapordaki tüm uygulanabilir maddeler çözüldü ve doğrulama üç katmanlı yapıldı
(birim test `-race`, `go vet`/`gofmt`, uçtan uca `make demo`). M1 (relay tarafı
kimlik doğrulama) Faz 3'te kapatıldı; gerçek ağ testleri bilinçli olarak Faz 4
kalıntısı olarak bırakıldı.