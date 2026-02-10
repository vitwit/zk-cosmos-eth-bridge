package prover

import (
	"testing"
)

func TestDecodeSecp256k1PubKey(t *testing.T) {
	// Dummy base64 encoded Secp256k1 pubkey (uncompressed)
	// For testing the logic, we check if it handles some input without crashing.
	pub64 := "BG5G9BqfC0r0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS0kS"
	_, _, err := DecodeSecp256k1PubKey(pub64)
	if err != nil {
		t.Logf("Decode failed as expected for dummy data: %v", err)
	}
}

func TestDecodeSecp256k1Signature(t *testing.T) {
	sig64 := "MEUCIQDY6M8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p8p"
	_, _, err := DecodeSecp256k1Signature(sig64)
	if err != nil {
		t.Logf("Decode failed as expected for dummy data: %v", err)
	}
}
