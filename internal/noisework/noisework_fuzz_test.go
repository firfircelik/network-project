package noisework

import "testing"

// FuzzResponderMessages feeds arbitrary bytes into the responder's handshake
// message readers. Neither step may panic; every malformed input must surface
// as an error.
func FuzzResponderMessages(f *testing.F) {
	initKP, err := GenerateKeypair()
	if err != nil {
		f.Fatalf("GenerateKeypair: %v", err)
	}
	respKP, err := GenerateKeypair()
	if err != nil {
		f.Fatalf("GenerateKeypair: %v", err)
	}
	init, err := NewInitiator(initKP, respKP.Public, testPrologue)
	if err != nil {
		f.Fatalf("NewInitiator: %v", err)
	}
	msg1, err := init.Message1()
	if err != nil {
		f.Fatalf("Message1: %v", err)
	}
	f.Add(msg1)
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(make([]byte, 65535))

	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewResponder(respKP, testPrologue)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}
		// ReadMessage1 on garbage must error, never panic.
		if err := r.ReadMessage1(data); err != nil {
			return
		}
		// Only a structurally valid msg1 reaches Message2/ReadMessage3.
		if _, err := r.Message2(); err != nil {
			return
		}
		// Garbage in the final step must error, never panic.
		_, _ = r.ReadMessage3(data)
	})
}

// FuzzInitiatorReadMessage2 feeds arbitrary bytes into the initiator's second
// handshake step.
func FuzzInitiatorReadMessage2(f *testing.F) {
	initKP, err := GenerateKeypair()
	if err != nil {
		f.Fatalf("GenerateKeypair: %v", err)
	}
	respKP, err := GenerateKeypair()
	if err != nil {
		f.Fatalf("GenerateKeypair: %v", err)
	}
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x02, 0x03})
	f.Add(make([]byte, 65535))

	f.Fuzz(func(t *testing.T, data []byte) {
		init, err := NewInitiator(initKP, respKP.Public, testPrologue)
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		if _, err := init.Message1(); err != nil {
			t.Fatalf("Message1: %v", err)
		}
		// Garbage must error, never panic.
		_, _ = init.ReadMessage2(data)
	})
}
