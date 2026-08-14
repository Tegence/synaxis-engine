package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const encPrefix = "enc:v1:"

var (
	// ErrCipherUnavailable means an encrypted value was encountered without a
	// usable cipher. Callers must fail closed rather than treating ciphertext as
	// a credential.
	ErrCipherUnavailable = errors.New("encryption cipher is unavailable")
	// ErrInvalidCiphertext is deliberately content-free: callers can surface it
	// without leaking a token or recorded payload into a log or response.
	ErrInvalidCiphertext = errors.New("invalid encrypted value")
)

// entropyReader is a seam for testing an entropy failure. Production always
// uses crypto/rand.Reader.
var entropyReader io.Reader = rand.Reader

// Cipher encrypts sensitive token fields at rest with AES-256-GCM. Values
// written before encryption was enabled have no enc: prefix and decrypt as
// plaintext — so existing rows keep working, and EncryptExisting upgrades them.
type Cipher struct{ aead cipher.AEAD }

// NewCipher builds a cipher from a base64 (std or url) encoded 32-byte key.
func NewCipher(keyB64 string) (*Cipher, error) {
	key, err := decodeKey(keyB64)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("ENGINE_ENCRYPTION_KEY must decode to 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead}, nil
}

func decodeKey(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// Encrypt returns an enc:-prefixed ciphertext. A nil cipher deliberately
// preserves the plaintext-only self-hosted FileStore/Postgres development
// mode, but any actual encryption failure is returned to the caller: writing
// the plaintext as a fallback would silently defeat at-rest encryption.
func (c *Cipher) Encrypt(plain string) (string, error) {
	if plain == "" {
		return plain, nil
	}
	if c == nil {
		if strings.HasPrefix(plain, encPrefix) {
			return "", fmt.Errorf("%w: ENGINE_ENCRYPTION_KEY is required to preserve encrypted data", ErrCipherUnavailable)
		}
		return plain, nil
	}
	if c.aead == nil {
		return "", ErrCipherUnavailable
	}
	if strings.HasPrefix(plain, encPrefix) {
		// Idempotency is useful during migrations, but only preserve ciphertext
		// that this configured key can authenticate.
		if _, err := c.Decrypt(plain); err != nil {
			return "", err
		}
		return plain, nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(entropyReader, nonce); err != nil {
		return "", fmt.Errorf("generate encryption nonce: %w", err)
	}
	ct := c.aead.Seal(nonce, nonce, []byte(plain), nil)
	return encPrefix + base64.RawStdEncoding.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt; un-prefixed input is treated as legacy plaintext.
// Corrupt, mismatched-key, or unavailable-cipher values return an error rather
// than the ambiguous empty string used by the old implementation.
func (c *Cipher) Decrypt(s string) (string, error) {
	if !strings.HasPrefix(s, encPrefix) {
		return s, nil
	}
	if c == nil || c.aead == nil {
		return "", fmt.Errorf("%w: ENGINE_ENCRYPTION_KEY is required to read encrypted data", ErrCipherUnavailable)
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(s, encPrefix))
	if err != nil || len(raw) < c.aead.NonceSize() {
		return "", ErrInvalidCiphertext
	}
	nonce, ct := raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():]
	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", ErrInvalidCiphertext
	}
	return string(pt), nil
}
