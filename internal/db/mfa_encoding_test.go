package db

import (
	"testing"

	"github.com/swayrider/swlib/encryption"
)

// testKeyRing is defined in jwt_keys_encoding_test.go (same package) and
// builds a deterministic ring whose key bytes are all seed.

func TestEncryptSecret_RoundTrip(t *testing.T) {
	ring := testKeyRing(t, 1)
	secret := "JBSWY3DPEHPK3PXP"

	value, keyID, err := encryptSecret(secret, ring)
	if err != nil {
		t.Fatalf("encryptSecret failed: %v", err)
	}
	if keyID == "" {
		t.Error("expected a non-empty key id")
	}
	if value == secret {
		t.Error("expected the stored value to differ from the plaintext secret")
	}

	got, err := decryptSecret(value, keyID, ring)
	if err != nil {
		t.Fatalf("decryptSecret failed: %v", err)
	}
	if got != secret {
		t.Errorf("roundtrip mismatch: got %q, want %q", got, secret)
	}
}

func TestEncryptSecret_NilRingPlaintext(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"

	value, keyID, err := encryptSecret(secret, nil)
	if err != nil {
		t.Fatalf("encryptSecret failed: %v", err)
	}
	if value != secret {
		t.Errorf("expected plaintext storage with nil ring, got %q", value)
	}
	if keyID != "" {
		t.Errorf("expected empty key id with nil ring, got %q", keyID)
	}

	got, err := decryptSecret(value, "", nil)
	if err != nil {
		t.Fatalf("decryptSecret with nil ring failed: %v", err)
	}
	if got != secret {
		t.Errorf("expected plaintext passthrough with nil ring, got %q", got)
	}
}

func TestDecryptSecret_WrongKeyFails(t *testing.T) {
	ring := testKeyRing(t, 1)
	otherRing := testKeyRing(t, 2)

	value, keyID, err := encryptSecret("JBSWY3DPEHPK3PXP", ring)
	if err != nil {
		t.Fatalf("encryptSecret failed: %v", err)
	}

	if _, err := decryptSecret(value, keyID, otherRing); err == nil {
		t.Error("expected an error decrypting under a different key")
	}
}

func TestDecryptSecret_DroppedKeyFails(t *testing.T) {
	droppedRing := testKeyRing(t, 3)
	value, keyID, err := encryptSecret("JBSWY3DPEHPK3PXP", droppedRing)
	if err != nil {
		t.Fatalf("encryptSecret failed: %v", err)
	}

	// The key used at write time is configured on neither the current nor
	// previous slot of the new ring.
	currentRing := testKeyRing(t, 4)
	if _, err := decryptSecret(value, keyID, currentRing); err == nil {
		t.Error("expected an error decrypting a secret under a fully retired key")
	}
}

func TestDecryptSecret_ViaPreviousKey(t *testing.T) {
	oldKeyBytes := make([]byte, encryption.KeySize)
	for i := range oldKeyBytes {
		oldKeyBytes[i] = 1
	}
	newKeyBytes := make([]byte, encryption.KeySize)
	for i := range newKeyBytes {
		newKeyBytes[i] = 2
	}

	oldRing := encryption.NewKeyRing(oldKeyBytes, nil)
	value, keyID, err := encryptSecret("JBSWY3DPEHPK3PXP", oldRing)
	if err != nil {
		t.Fatalf("encryptSecret failed: %v", err)
	}

	// After rotation: current key is new, old key demoted to previous.
	rotatedRing := encryption.NewKeyRing(newKeyBytes, [][]byte{oldKeyBytes})

	got, err := decryptSecret(value, keyID, rotatedRing)
	if err != nil {
		t.Fatalf("decryptSecret via previous key failed: %v", err)
	}
	if got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("roundtrip mismatch: got %q", got)
	}
}
