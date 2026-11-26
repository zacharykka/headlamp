package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestParseKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0xab}, KeySize)

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "hex", input: hex.EncodeToString(raw)},
		{name: "hex with whitespace", input: "  " + hex.EncodeToString(raw) + "\n"},
		{name: "base64 std", input: base64.StdEncoding.EncodeToString(raw)},
		{name: "base64 raw std", input: base64.RawStdEncoding.EncodeToString(raw)},
		{name: "base64 url", input: base64.URLEncoding.EncodeToString(raw)},
		{name: "base64 raw url", input: base64.RawURLEncoding.EncodeToString(raw)},
		{name: "empty", input: "", wantErr: true},
		{name: "too short hex", input: hex.EncodeToString(raw[:16]), wantErr: true},
		{name: "too short base64", input: base64.StdEncoding.EncodeToString(raw[:16]), wantErr: true},
		{name: "garbage", input: "not-a-valid-key!!!", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseKey(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got key of len %d", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(got, raw) {
				t.Fatalf("decoded key mismatch")
			}
		})
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	inputs := []string{"", "sk-ant-api03-secret-token", "unicode-密钥-🔑"}
	for _, plaintext := range inputs {
		enc1, err := c.EncryptString(plaintext)
		if err != nil {
			t.Fatalf("EncryptString(%q): %v", plaintext, err)
		}
		enc2, err := c.EncryptString(plaintext)
		if err != nil {
			t.Fatalf("EncryptString second(%q): %v", plaintext, err)
		}
		if !IsEncrypted(enc1) {
			t.Fatalf("expected IsEncrypted to be true for %q", enc1)
		}
		if enc1 == enc2 {
			t.Fatalf("expected distinct ciphertexts due to random nonces")
		}
		dec, err := c.DecryptString(enc1)
		if err != nil {
			t.Fatalf("DecryptString: %v", err)
		}
		if dec != plaintext {
			t.Fatalf("got %q, want %q", dec, plaintext)
		}
	}
}

func TestDecryptRejectsTamperingAndWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	c1, _ := NewCipher(key1)
	c2, _ := NewCipher(key2)

	raw, err := c1.Encrypt([]byte("top-secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := c2.Decrypt(raw); err == nil {
		t.Fatal("expected decryption with wrong key to fail")
	}

	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := c1.Decrypt(tampered); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}

	wrongVersion := append([]byte(nil), raw...)
	wrongVersion[0] = 0x02
	if _, err := c1.Decrypt(wrongVersion); err == nil {
		t.Fatal("expected unsupported version to fail")
	}

	if _, err := c1.DecryptString("plaintext-not-prefixed"); err == nil {
		t.Fatal("expected missing prefix to fail")
	}
}

func TestLoadOrCreateKeyPersists0600(t *testing.T) {
	dir := t.TempDir()

	// First run auto-generates and writes 0600 key file.
	k1, generated, keyPath, err := LoadOrCreateKey("", dir)
	if err != nil {
		t.Fatalf("first LoadOrCreateKey: %v", err)
	}
	if !generated {
		t.Fatal("expected generated=true on first run")
	}
	wantPath := filepath.Join(dir, DefaultKeyFilename)
	if keyPath != wantPath {
		t.Fatalf("keyPath = %q, want %q", keyPath, wantPath)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file permissions = %04o, want 0600", perm)
	}

	// Second run reloads the same key without regenerating.
	k2, generated2, keyPath2, err := LoadOrCreateKey("", dir)
	if err != nil {
		t.Fatalf("second LoadOrCreateKey: %v", err)
	}
	if generated2 {
		t.Fatal("expected generated=false on second run")
	}
	if keyPath2 != wantPath {
		t.Fatalf("keyPath2 = %q, want %q", keyPath2, wantPath)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("reloaded key differs from generated key")
	}

	// Explicit env value takes precedence over state_dir.
	envKeyBytes := bytes.Repeat([]byte{0x42}, KeySize)
	envHex := hex.EncodeToString(envKeyBytes)
	k3, generated3, keyPath3, err := LoadOrCreateKey(envHex, dir)
	if err != nil {
		t.Fatalf("env LoadOrCreateKey: %v", err)
	}
	if generated3 || keyPath3 != "" {
		t.Fatalf("expected generated=false and empty keyPath, got (%v, %q)", generated3, keyPath3)
	}
	if !bytes.Equal(k3, envKeyBytes) {
		t.Fatal("env key mismatch")
	}
}
