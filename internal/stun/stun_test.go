package stun

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestEncodeBindingRequest(t *testing.T) {
	txid := NewTransactionID()
	var zero [12]byte
	if bytes.Equal(txid[:], zero[:]) {
		t.Fatal("NewTransactionID returned all-zero id")
	}
	pkt := EncodeBindingRequest(txid)
	if len(pkt) != stunHeaderLen {
		t.Fatalf("len = %d, want %d", len(pkt), stunHeaderLen)
	}
	if typ := binary.BigEndian.Uint16(pkt[0:2]); typ != 0x0001 {
		t.Fatalf("type = 0x%04x, want 0x0001", typ)
	}
	if l := binary.BigEndian.Uint16(pkt[2:4]); l != 0 {
		t.Fatalf("length = %d, want 0", l)
	}
	if c := binary.BigEndian.Uint32(pkt[4:8]); c != 0x2112A442 {
		t.Fatalf("cookie = 0x%08x, want 0x2112A442", c)
	}
	if !bytes.Equal(pkt[8:20], txid[:]) {
		t.Fatalf("txid mismatch")
	}
}

func TestHandleAndDecodeIPv4(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("192.0.2.55"), Port: 4321}
	resp, err := HandleBindingRequest(EncodeBindingRequest(NewTransactionID()), src)
	if err != nil {
		t.Fatalf("HandleBindingRequest: %v", err)
	}
	addr, err := DecodeXORMappedAddress(resp)
	if err != nil {
		t.Fatalf("DecodeXORMappedAddress: %v", err)
	}
	if !addr.IP.Equal(src.IP) || addr.Port != src.Port {
		t.Fatalf("got %s, want %s", addr, src)
	}
}

func TestHandleAndDecodeIPv6(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("2001:db8::abcd"), Port: 1234}
	resp, err := HandleBindingRequest(EncodeBindingRequest(NewTransactionID()), src)
	if err != nil {
		t.Fatalf("HandleBindingRequest: %v", err)
	}
	addr, err := DecodeXORMappedAddress(resp)
	if err != nil {
		t.Fatalf("DecodeXORMappedAddress: %v", err)
	}
	if !addr.IP.Equal(src.IP) || addr.Port != src.Port {
		t.Fatalf("got %s, want %s", addr, src)
	}
}

func TestDecodeErrors(t *testing.T) {
	req := EncodeBindingRequest(NewTransactionID())
	if _, err := DecodeXORMappedAddress(req); err == nil {
		t.Fatal("binding request accepted as response")
	}

	resp, err := HandleBindingRequest(req, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	if err != nil {
		t.Fatalf("HandleBindingRequest: %v", err)
	}

	// Truncated header and truncated attribute area.
	for _, bad := range [][]byte{resp[:19], resp[:20], resp[:29]} {
		if _, err := DecodeXORMappedAddress(bad); err == nil {
			t.Fatalf("truncated packet of %d bytes accepted", len(bad))
		}
	}

	// Tampered magic cookie.
	bad := append([]byte(nil), resp...)
	bad[4] ^= 0xFF
	if _, err := DecodeXORMappedAddress(bad); err == nil {
		t.Fatal("invalid magic cookie accepted")
	}

	// Tampered message type.
	bad = append([]byte(nil), resp...)
	bad[1] = 0x00 // 0x0101 -> 0x0100
	if _, err := DecodeXORMappedAddress(bad); err == nil {
		t.Fatal("non-response message type accepted")
	}

	// Response without XOR-MAPPED-ADDRESS attribute.
	txid := NewTransactionID()
	noAttr := make([]byte, 24)
	binary.BigEndian.PutUint16(noAttr[0:2], 0x0101)
	binary.BigEndian.PutUint16(noAttr[2:4], 4)
	binary.BigEndian.PutUint32(noAttr[4:8], 0x2112A442)
	copy(noAttr[8:20], txid[:])
	binary.BigEndian.PutUint16(noAttr[20:22], 0x0001) // MAPPED-ADDRESS, length 0
	binary.BigEndian.PutUint16(noAttr[22:24], 0)
	if _, err := DecodeXORMappedAddress(noAttr); err == nil {
		t.Fatal("response without XOR-MAPPED-ADDRESS accepted")
	}
}

func TestResolvePublicAddrRoundtrip(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	srv := server.(*net.UDPConn)
	defer srv.Close()

	go func() {
		buf := make([]byte, 65536)
		for {
			n, src, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp, err := HandleBindingRequest(buf[:n], src)
			if err != nil {
				continue
			}
			_, _ = srv.WriteToUDP(resp, src)
		}
	}()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	cc := client.(*net.UDPConn)
	defer cc.Close()

	addr, err := ResolvePublicAddr(cc, srv.LocalAddr().(*net.UDPAddr), 2*time.Second)
	if err != nil {
		t.Fatalf("ResolvePublicAddr: %v", err)
	}
	if addr == nil {
		t.Fatal("ResolvePublicAddr returned nil address")
	}
	local := cc.LocalAddr().(*net.UDPAddr)
	if !addr.IP.Equal(local.IP) || addr.Port != local.Port {
		t.Fatalf("resolved %s, want %s (client's own effective address)", addr, local)
	}

	// The client socket must remain bound to the same address after the
	// roundtrip (NAT mapping consistency).
	if after := cc.LocalAddr().(*net.UDPAddr); after.Port != local.Port {
		t.Fatalf("client socket port changed from %d to %d", local.Port, after.Port)
	}
}

func TestResolvePublicAddrIPv6(t *testing.T) {
	server, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	srv := server.(*net.UDPConn)
	defer srv.Close()

	go func() {
		buf := make([]byte, 65536)
		for {
			n, src, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp, err := HandleBindingRequest(buf[:n], src)
			if err != nil {
				continue
			}
			_, _ = srv.WriteToUDP(resp, src)
		}
	}()

	client, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback client unavailable: %v", err)
	}
	cc := client.(*net.UDPConn)
	defer cc.Close()

	addr, err := ResolvePublicAddr(cc, srv.LocalAddr().(*net.UDPAddr), 2*time.Second)
	if err != nil {
		t.Fatalf("ResolvePublicAddr over IPv6: %v", err)
	}
	local := cc.LocalAddr().(*net.UDPAddr)
	if !addr.IP.Equal(local.IP) || addr.Port != local.Port {
		t.Fatalf("resolved %s, want %s", addr, local)
	}
}
