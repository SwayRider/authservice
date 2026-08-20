package db

import (
	"testing"

	"github.com/swayrider/swlib/crypto"
	"github.com/swayrider/swlib/encryption"
)

func testKeyRing(t *testing.T, seed byte) *encryption.KeyRing {
	t.Helper()
	key := make([]byte, encryption.KeySize)
	for i := range key {
		key[i] = seed
	}
	return encryption.NewKeyRing(key, nil)
}

func TestEncodeForStorage_Encrypted(t *testing.T) {
	ring := testKeyRing(t, 1)
	privPEM := "-----BEGIN RSA PRIVATE KEY-----\nfake key data\n-----END RSA PRIVATE KEY-----\n"

	value, encrypted, keyID, err := encodeForStorage(privPEM, ring)
	if err != nil {
		t.Fatalf("encodeForStorage failed: %v", err)
	}
	if !encrypted {
		t.Error("expected encrypted to be true")
	}
	if keyID == "" {
		t.Error("expected a non-empty key id")
	}
	if value == privPEM {
		t.Error("expected the stored value to differ from the plaintext PEM")
	}

	got, err := decodeFromStorage(value, encrypted, keyID, ring)
	if err != nil {
		t.Fatalf("decodeFromStorage failed: %v", err)
	}
	if got != privPEM {
		t.Errorf("roundtrip mismatch: got %q, want %q", got, privPEM)
	}
}

func TestDecodeFromStorage_PlaintextPassthrough(t *testing.T) {
	privPEM := "-----BEGIN RSA PRIVATE KEY-----\nlegacy plaintext row\n-----END RSA PRIVATE KEY-----\n"
	ring := testKeyRing(t, 1)

	// isEncrypted == false must return the value verbatim regardless of the
	// ring, since this is how pre-existing plaintext rows stay readable.
	got, err := decodeFromStorage(privPEM, false, "", ring)
	if err != nil {
		t.Fatalf("decodeFromStorage failed: %v", err)
	}
	if got != privPEM {
		t.Errorf("expected plaintext passthrough, got %q", got)
	}

	got, err = decodeFromStorage(privPEM, false, "", nil)
	if err != nil {
		t.Fatalf("decodeFromStorage with nil ring failed: %v", err)
	}
	if got != privPEM {
		t.Errorf("expected plaintext passthrough with nil ring, got %q", got)
	}
}

func TestDecodeFromStorage_ViaPreviousKey(t *testing.T) {
	oldKeyBytes := make([]byte, encryption.KeySize)
	for i := range oldKeyBytes {
		oldKeyBytes[i] = 1
	}
	newKeyBytes := make([]byte, encryption.KeySize)
	for i := range newKeyBytes {
		newKeyBytes[i] = 2
	}

	oldRing := encryption.NewKeyRing(oldKeyBytes, nil)
	privPEM := "-----BEGIN RSA PRIVATE KEY-----\npre-rotation key\n-----END RSA PRIVATE KEY-----\n"
	value, encrypted, keyID, err := encodeForStorage(privPEM, oldRing)
	if err != nil {
		t.Fatalf("encodeForStorage failed: %v", err)
	}

	// After rotation: the ring's current key is new, old key demoted to previous.
	rotatedRing := encryption.NewKeyRing(newKeyBytes, [][]byte{oldKeyBytes})

	got, err := decodeFromStorage(value, encrypted, keyID, rotatedRing)
	if err != nil {
		t.Fatalf("decodeFromStorage via previous key failed: %v", err)
	}
	if got != privPEM {
		t.Errorf("roundtrip mismatch: got %q, want %q", got, privPEM)
	}
}

func TestDecodeFromStorage_DroppedKeyFails(t *testing.T) {
	droppedKeyBytes := make([]byte, encryption.KeySize)
	for i := range droppedKeyBytes {
		droppedKeyBytes[i] = 3
	}
	droppedRing := encryption.NewKeyRing(droppedKeyBytes, nil)

	value, encrypted, keyID, err := encodeForStorage("-----BEGIN RSA PRIVATE KEY-----\nold\n-----END RSA PRIVATE KEY-----\n", droppedRing)
	if err != nil {
		t.Fatalf("encodeForStorage failed: %v", err)
	}

	// The dropped key is configured on neither the current nor previous slot.
	currentRing := testKeyRing(t, 4)
	if _, err := decodeFromStorage(value, encrypted, keyID, currentRing); err == nil {
		t.Error("expected an error decoding a row encrypted under a fully retired key")
	}
}

func TestEncodeForStorage_RoundTripsRealKeypair(t *testing.T) {
	privPEM, _, _, err := crypto.CreateKeypair()
	if err != nil {
		t.Fatalf("CreateKeypair failed: %v", err)
	}

	ring := testKeyRing(t, 5)
	value, encrypted, keyID, err := encodeForStorage(privPEM, ring)
	if err != nil {
		t.Fatalf("encodeForStorage failed: %v", err)
	}

	got, err := decodeFromStorage(value, encrypted, keyID, ring)
	if err != nil {
		t.Fatalf("decodeFromStorage failed: %v", err)
	}
	if got != privPEM {
		t.Error("roundtrip mismatch for a real generated RSA private key PEM")
	}
}
