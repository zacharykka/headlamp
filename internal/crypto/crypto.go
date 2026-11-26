package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// KeySize is the required AES-256 key length in bytes.
	KeySize = 32

	// DefaultKeyFilename is the filename used when auto-generating a master key inside state_dir.
	DefaultKeyFilename = "master.key"

	formatVersion byte = 0x01
	stringPrefix       = "enc:v1:"
)

// Cipher encrypts and decrypts secrets using AES-256-GCM.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher builds an AES-256-GCM Cipher from a raw 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: master key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: init aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: init gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// GenerateKey returns a cryptographically random 32-byte AES-256 key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("crypto: generate random key: %w", err)
	}
	return key, nil
}

// ParseKey decodes a 32-byte master key from 64-character hex or standard/URL base64.
func ParseKey(encoded string) ([]byte, error) {
	s := strings.TrimSpace(encoded)
	if s == "" {
		return nil, errors.New("crypto: master key is empty")
	}

	if len(s) == hex.EncodedLen(KeySize) {
		if raw, err := hex.DecodeString(s); err == nil && len(raw) == KeySize {
			return raw, nil
		}
	}

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if raw, err := enc.DecodeString(s); err == nil && len(raw) == KeySize {
			return raw, nil
		}
	}

	return nil, fmt.Errorf("crypto: master key must be a 32-byte hex or base64 string")
}

// LoadOrCreateKey resolves the master key from envValue (HEADLAMP_MASTER_KEY) if set,
// otherwise loads or auto-generates a 0600 key file at <stateDir>/master.key.
// When generated is true, callers should inform operators to back up keyPath.
func LoadOrCreateKey(envValue, stateDir string) (key []byte, generated bool, keyPath string, err error) {
	if strings.TrimSpace(envValue) != "" {
		key, err = ParseKey(envValue)
		if err != nil {
			return nil, false, "", err
		}
		return key, false, "", nil
	}

	if strings.TrimSpace(stateDir) == "" {
		return nil, false, "", errors.New("crypto: state_dir is required when HEADLAMP_MASTER_KEY is not set")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, false, "", fmt.Errorf("crypto: create state_dir %q: %w", stateDir, err)
	}

	keyPath = filepath.Join(stateDir, DefaultKeyFilename)
	data, err := os.ReadFile(keyPath)
	if err == nil {
		key, err = ParseKey(string(data))
		if err != nil {
			return nil, false, keyPath, fmt.Errorf("crypto: invalid key file %q: %w", keyPath, err)
		}
		return key, false, keyPath, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, keyPath, fmt.Errorf("crypto: read key file %q: %w", keyPath, err)
	}

	key, err = GenerateKey()
	if err != nil {
		return nil, false, keyPath, err
	}

	f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// Another process created the key concurrently; read the persisted key.
			existing, readErr := os.ReadFile(keyPath)
			if readErr != nil {
				return nil, false, keyPath, fmt.Errorf("crypto: read concurrently created key file %q: %w", keyPath, readErr)
			}
			key, parseErr := ParseKey(string(existing))
			if parseErr != nil {
				return nil, false, keyPath, fmt.Errorf("crypto: invalid key file %q: %w", keyPath, parseErr)
			}
			return key, false, keyPath, nil
		}
		return nil, false, keyPath, fmt.Errorf("crypto: create key file %q: %w", keyPath, err)
	}

	encoded := hex.EncodeToString(key) + "\n"
	_, writeErr := f.WriteString(encoded)
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(keyPath)
		return nil, false, keyPath, fmt.Errorf("crypto: write key file %q: %w", keyPath, writeErr)
	}
	if closeErr != nil {
		return nil, false, keyPath, fmt.Errorf("crypto: close key file %q: %w", keyPath, closeErr)
	}
	// Ensure 0600 permissions regardless of process umask.
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return nil, false, keyPath, fmt.Errorf("crypto: chmod key file %q: %w", keyPath, err)
	}

	return key, true, keyPath, nil
}

// NewCipherFromEnvOrDir loads or creates the master key and returns a ready Cipher.
func NewCipherFromEnvOrDir(envValue, stateDir string) (*Cipher, bool, string, error) {
	key, generated, keyPath, err := LoadOrCreateKey(envValue, stateDir)
	if err != nil {
		return nil, false, keyPath, err
	}
	c, err := NewCipher(key)
	if err != nil {
		return nil, false, keyPath, err
	}
	return c, generated, keyPath, nil
}

// Encrypt encrypts plaintext into version(1 byte) || nonce || ciphertext+tag.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}

	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+c.aead.Overhead())
	out = append(out, formatVersion)
	out = append(out, nonce...)
	out = c.aead.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// Decrypt decrypts bytes produced by Encrypt.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	minLen := 1 + c.aead.NonceSize() + c.aead.Overhead()
	if len(ciphertext) < minLen {
		return nil, errors.New("crypto: ciphertext too short")
	}
	if ciphertext[0] != formatVersion {
		return nil, fmt.Errorf("crypto: unsupported ciphertext version 0x%02x", ciphertext[0])
	}

	nonceEnd := 1 + c.aead.NonceSize()
	nonce := ciphertext[1:nonceEnd]
	sealed := ciphertext[nonceEnd:]

	plaintext, err := c.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt failed: %w", err)
	}
	return plaintext, nil
}

// EncryptString encrypts plaintext and returns a self-describing "enc:v1:<base64>" string.
func (c *Cipher) EncryptString(plaintext string) (string, error) {
	raw, err := c.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return stringPrefix + base64.StdEncoding.EncodeToString(raw), nil
}

// DecryptString decrypts a string produced by EncryptString.
func (c *Cipher) DecryptString(ciphertext string) (string, error) {
	if !strings.HasPrefix(ciphertext, stringPrefix) {
		return "", errors.New("crypto: invalid encrypted string prefix")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertext, stringPrefix))
	if err != nil {
		return "", fmt.Errorf("crypto: decode encrypted string: %w", err)
	}
	plaintext, err := c.Decrypt(raw)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// IsEncrypted reports whether s carries Headlamp's encrypted string prefix.
func IsEncrypted(s string) bool {
	return strings.HasPrefix(s, stringPrefix)
}
