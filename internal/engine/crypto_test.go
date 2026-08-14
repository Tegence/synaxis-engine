package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func testCipher(t *testing.T, fill byte) *Cipher {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	cipher, err := NewCipher(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return cipher
}

func TestCipherEncryptDecryptRoundTrip(t *testing.T) {
	cipher := testCipher(t, 7)
	ciphertext, err := cipher.Encrypt("provider-token")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(ciphertext, encPrefix) || strings.Contains(ciphertext, "provider-token") {
		t.Fatalf("ciphertext = %q, want non-plaintext %s value", ciphertext, encPrefix)
	}
	plain, err := cipher.Decrypt(ciphertext)
	if err != nil || plain != "provider-token" {
		t.Fatalf("Decrypt = %q, %v", plain, err)
	}
	legacy, err := cipher.Decrypt("legacy-plain")
	if err != nil || legacy != "legacy-plain" {
		t.Fatalf("legacy Decrypt = %q, %v", legacy, err)
	}

	// Re-applying a configured cipher to a value it already authenticated is
	// migration-safe and does not produce needless new ciphertext.
	again, err := cipher.Encrypt(ciphertext)
	if err != nil || again != ciphertext {
		t.Fatalf("idempotent Encrypt = %q, %v", again, err)
	}
}

func TestCipherFailuresNeverMasqueradeAsPlaintext(t *testing.T) {
	cipher := testCipher(t, 11)

	oldEntropy := entropyReader
	entropyReader = failingEntropyReader{}
	t.Cleanup(func() { entropyReader = oldEntropy })
	ciphertext, err := cipher.Encrypt("do-not-store-me-plain")
	if err == nil {
		t.Fatal("Encrypt accepted an entropy failure")
	}
	if ciphertext != "" || ciphertext == "do-not-store-me-plain" {
		t.Fatalf("Encrypt fallback = %q, want empty value with error", ciphertext)
	}

	for _, value := range []string{encPrefix, encPrefix + "not-base64"} {
		plain, err := cipher.Decrypt(value)
		if !errors.Is(err, ErrInvalidCiphertext) {
			t.Fatalf("Decrypt(%q) error = %v, want ErrInvalidCiphertext", value, err)
		}
		if plain != "" {
			t.Fatalf("Decrypt(%q) = %q, want no ambiguous value", value, plain)
		}
	}
}

func TestCipherRejectsMissingOrMismatchedKey(t *testing.T) {
	first := testCipher(t, 1)
	ciphertext, err := first.Encrypt("provider-token")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var absent *Cipher
	if _, err := absent.Decrypt(ciphertext); !errors.Is(err, ErrCipherUnavailable) {
		t.Fatalf("nil cipher decrypt error = %v, want ErrCipherUnavailable", err)
	}
	second := testCipher(t, 2)
	if _, err := second.Decrypt(ciphertext); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("wrong-key decrypt error = %v, want ErrInvalidCiphertext", err)
	}
}

func TestPgStoreCryptoGuardsRejectUnsafePersistenceInputs(t *testing.T) {
	if err := (&PgStore{}).EncryptExisting(context.Background()); !errors.Is(err, ErrCipherUnavailable) {
		t.Fatalf("EncryptExisting without cipher error = %v, want ErrCipherUnavailable", err)
	}

	store := &PgStore{cipher: testCipher(t, 9)}
	_, _, _, _, err := store.encryptAccountSecrets(Account{AccessToken: encPrefix + "not-base64"})
	if !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("encryptAccountSecrets malformed ciphertext error = %v, want ErrInvalidCiphertext", err)
	}
}

type failingEntropyReader struct{}

func (failingEntropyReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}
