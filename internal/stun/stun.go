// Package stun implements a minimal RFC 8489 (STUN) binding protocol used by
// the meshlink NAT simulator for mapping discovery: binding request/response
// encoding, XOR-MAPPED-ADDRESS parsing, and public address resolution over a
// real UDP socket.
package stun

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// STUN protocol constants (RFC 8489).
const (
	messageTypeBindingRequest  = 0x0001
	messageTypeBindingResponse = 0x0101
	attrXORMappedAddress       = 0x0020
	stunMagicCookie            = 0x2112A442
	stunHeaderLen              = 20
	xorPortMask                = uint16(0x2112) // upper 16 bits of the magic cookie
)

// EncodeBindingRequest builds a minimal binding request datagram (RFC 8489
// §6): message type 0x0001, zero message length, the magic cookie and the
// given 12-byte transaction id.
func EncodeBindingRequest(txid [12]byte) []byte {
	return stunHeader(messageTypeBindingRequest, 0, txid[:])
}

// NewTransactionID returns a fresh 12-byte random transaction id.
func NewTransactionID() [12]byte {
	var t [12]byte
	if _, err := rand.Read(t[:]); err != nil {
		// crypto/rand cannot fail on supported platforms and this API has no
		// error return, so a failure here is unrecoverable.
		panic(fmt.Sprintf("stun: crypto/rand read failed: %v", err))
	}
	return t
}

// HandleBindingRequest produces a binding response (type 0x0101) that echoes
// the transaction id from pkt and carries an XOR-MAPPED-ADDRESS attribute for
// src (IPv4 or IPv6). No fingerprint attribute is emitted.
func HandleBindingRequest(pkt []byte, src *net.UDPAddr) ([]byte, error) {
	if len(pkt) < stunHeaderLen {
		return nil, fmt.Errorf("stun: request too short: %d < %d bytes", len(pkt), stunHeaderLen)
	}
	if typ := binary.BigEndian.Uint16(pkt[0:2]); typ != messageTypeBindingRequest {
		return nil, fmt.Errorf("stun: not a binding request (type 0x%04x)", typ)
	}
	if c := binary.BigEndian.Uint32(pkt[4:8]); c != stunMagicCookie {
		return nil, fmt.Errorf("stun: invalid magic cookie 0x%08x", c)
	}
	if src == nil || src.IP == nil {
		return nil, errors.New("stun: nil source address")
	}
	family, addrBytes, err := splitAddress(src.IP)
	if err != nil {
		return nil, err
	}

	// Response: header, then XOR-MAPPED-ADDRESS (reserved, family, x-port,
	// x-address). Both IPv4 (8 bytes) and IPv6 (20 bytes) values are already
	// padded to a 4-byte boundary.
	attrLen := 4 + len(addrBytes)
	msgLen := 4 + attrLen
	resp := make([]byte, 0, stunHeaderLen+msgLen)
	resp = append(resp, stunHeader(messageTypeBindingResponse, uint16(msgLen), pkt[8:20])...)
	resp = binary.BigEndian.AppendUint16(resp, attrXORMappedAddress)
	resp = binary.BigEndian.AppendUint16(resp, uint16(attrLen))
	resp = append(resp, 0) // reserved, always zero
	resp = append(resp, family)
	resp = binary.BigEndian.AppendUint16(resp, uint16(src.Port)^xorPortMask)
	xaddr := make([]byte, len(addrBytes))
	for i := range xaddr {
		// resp[4:20] is the magic cookie followed by the echoed txid, i.e.
		// the 16-byte XOR key; for IPv4 the first four bytes (the cookie) are
		// enough.
		xaddr[i] = addrBytes[i] ^ resp[4+i]
	}
	resp = append(resp, xaddr...)
	return resp, nil
}

// DecodeXORMappedAddress validates pkt as a binding response (type 0x0101,
// matching magic cookie) and extracts the XOR-MAPPED-ADDRESS attribute,
// returning the mapped public address.
func DecodeXORMappedAddress(pkt []byte) (*net.UDPAddr, error) {
	if len(pkt) < stunHeaderLen {
		return nil, fmt.Errorf("stun: packet too short: %d < %d bytes", len(pkt), stunHeaderLen)
	}
	if typ := binary.BigEndian.Uint16(pkt[0:2]); typ != messageTypeBindingResponse {
		return nil, fmt.Errorf("stun: unexpected message type 0x%04x", typ)
	}
	if c := binary.BigEndian.Uint32(pkt[4:8]); c != stunMagicCookie {
		return nil, fmt.Errorf("stun: invalid magic cookie 0x%08x", c)
	}
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if len(pkt) < stunHeaderLen+msgLen {
		return nil, fmt.Errorf("stun: truncated packet: message length %d but only %d bytes available", msgLen, len(pkt)-stunHeaderLen)
	}

	attrs := pkt[stunHeaderLen : stunHeaderLen+msgLen]
	xor := pkt[4:20] // magic cookie || transaction id, the IPv6 XOR key
	for len(attrs) >= 4 {
		atyp := binary.BigEndian.Uint16(attrs[0:2])
		alen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if len(attrs) < 4+alen {
			return nil, fmt.Errorf("stun: truncated attribute 0x%04x: need %d bytes, have %d", atyp, alen, len(attrs)-4)
		}
		if atyp == attrXORMappedAddress {
			return parseXORMappedAddress(attrs[4:4+alen], xor)
		}
		step := 4 + (alen+3)&^3 // attribute value plus padding to 4 bytes
		if step > len(attrs) {
			break
		}
		attrs = attrs[step:]
	}
	return nil, errors.New("stun: response contains no XOR-MAPPED-ADDRESS attribute")
}

// ResolvePublicAddr sends a binding request to server over the given UDP
// connection and returns the public address the server observed, as encoded in
// the XOR-MAPPED-ADDRESS attribute of the response. The request is sent and
// the response is read on the same conn, which keeps the NAT mapping attached
// to that socket consistent. Reads time out after timeout.
func ResolvePublicAddr(conn *net.UDPConn, server *net.UDPAddr, timeout time.Duration) (*net.UDPAddr, error) {
	txid := NewTransactionID()
	if _, err := conn.WriteToUDP(EncodeBindingRequest(txid), server); err != nil {
		return nil, fmt.Errorf("stun: send binding request to %s: %w", server, err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("stun: set read deadline: %w", err)
	}
	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, fmt.Errorf("stun: binding response from %s timed out after %s", server, timeout)
			}
			return nil, fmt.Errorf("stun: read response from %s: %w", server, err)
		}
		pkt := buf[:n]
		addr, err := DecodeXORMappedAddress(pkt)
		if err != nil {
			continue // not a valid response; keep reading until the deadline
		}
		if len(pkt) >= stunHeaderLen && bytes.Equal(pkt[8:20], txid[:]) {
			return addr, nil
		}
	}
}

// stunHeader builds a 20-byte STUN message header.
func stunHeader(msgType, msgLen uint16, txid []byte) []byte {
	h := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(h[0:2], msgType)
	binary.BigEndian.PutUint16(h[2:4], msgLen)
	binary.BigEndian.PutUint32(h[4:8], stunMagicCookie)
	copy(h[8:20], txid)
	return h
}

// splitAddress maps a net.IP to its STUN address family byte and raw bytes.
func splitAddress(ip net.IP) (family byte, b []byte, err error) {
	if v4 := ip.To4(); v4 != nil {
		return 0x01, v4, nil
	}
	if v6 := ip.To16(); v6 != nil {
		return 0x02, v6, nil
	}
	return 0, nil, fmt.Errorf("stun: unsupported IP address %q", ip)
}

// parseXORMappedAddress decodes an XOR-MAPPED-ADDRESS attribute value using
// the 16-byte cookie||txid XOR key.
func parseXORMappedAddress(v, xor []byte) (*net.UDPAddr, error) {
	if len(v) < 4 {
		return nil, fmt.Errorf("stun: XOR-MAPPED-ADDRESS value too short: %d bytes", len(v))
	}
	if v[0] != 0 {
		return nil, fmt.Errorf("stun: reserved family byte non-zero: 0x%02x", v[0])
	}
	port := binary.BigEndian.Uint16(v[2:4]) ^ xorPortMask
	xaddr := v[4:]
	switch v[1] {
	case 0x01: // IPv4
		if len(xaddr) < 4 {
			return nil, errors.New("stun: truncated IPv4 address in XOR-MAPPED-ADDRESS")
		}
		ip := make(net.IP, 4)
		for i := range ip {
			ip[i] = xaddr[i] ^ xor[i]
		}
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil
	case 0x02: // IPv6
		if len(xaddr) < 16 {
			return nil, errors.New("stun: truncated IPv6 address in XOR-MAPPED-ADDRESS")
		}
		if len(xor) < 16 {
			return nil, errors.New("stun: missing IPv6 XOR key")
		}
		ip := make(net.IP, 16)
		for i := range ip {
			ip[i] = xaddr[i] ^ xor[i]
		}
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil
	default:
		return nil, fmt.Errorf("stun: unsupported address family 0x%02x", v[1])
	}
}
