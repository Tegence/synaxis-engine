package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

const encPrefix = "enc:v1:"

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

// Encrypt returns the enc:-prefixed ciphertext (nil cipher or empty/already-encrypted → unchanged).
func (c *Cipher) Encrypt(plain string) string {
	if c == nil || plain == "" || strings.HasPrefix(plain, encPrefix) {
		return plain
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plain
	}
	ct := c.aead.Seal(nonce, nonce, []byte(plain), nil)
	return encPrefix + base64.RawStdEncoding.EncodeToString(ct)
}

// Decrypt reverses Encrypt; un-prefixed input is treated as legacy plaintext.
func (c *Cipher) Decrypt(s string) string {
	if c == nil || !strings.HasPrefix(s, encPrefix) {
		return s
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(s, encPrefix))
	if err != nil || len(raw) < c.aead.NonceSize() {
		return ""
	}
	nonce, ct := raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():]
	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return ""
	}
	return string(pt)
}
