package stun

import (
	"net"
	"testing"
)

// FuzzDecodeXORMappedAddress exercises the binding-response decoder; it must
// never panic, even on truncated/random data.
func FuzzDecodeXORMappedAddress(f *testing.F) {
	f.Add(EncodeBindingRequest(NewTransactionID()))
	f.Add(make([]byte, 20))
	f.Add(make([]byte, 29))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeXORMappedAddress(data)
	})
}

// FuzzHandleBindingRequest exercises the server-side responder; any input must
// only ever produce nil or a well-formed response.
func FuzzHandleBindingRequest(f *testing.F) {
	f.Add(EncodeBindingRequest(NewTransactionID()))
	f.Add([]byte("garbage"))
	f.Add(make([]byte, 19))
	f.Fuzz(func(t *testing.T, data []byte) {
		src := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000}
		resp, err := HandleBindingRequest(data, src)
		if err == nil {
			// A successfully handled request must yield a decodable response.
			if _, derr := DecodeXORMappedAddress(resp); derr != nil {
				t.Fatalf("HandleBindingRequest produced undecodable response: %v", derr)
			}
		}
	})
}
