package keystore

import (
	"bytes"
	"crypto/aes"
	"math/big"
	"testing"
)

func TestLinuxDecryptRejectsMalformedAndNeverReturnsEmptySuccess(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{1}, 16)
	for _, input := range []struct {
		iv         []byte
		ciphertext []byte
	}{
		{iv: nil, ciphertext: nil},
		{iv: bytes.Repeat([]byte{1}, 15), ciphertext: bytes.Repeat([]byte{2}, 16)},
		{iv: bytes.Repeat([]byte{1}, 16), ciphertext: bytes.Repeat([]byte{2}, 15)},
		{iv: bytes.Repeat([]byte{1}, 16), ciphertext: bytes.Repeat([]byte{0}, 16)},
	} {
		plaintext, err := decryptLinuxSecret(key, input.iv, input.ciphertext)
		if err == nil || len(plaintext) != 0 {
			t.Fatalf("decrypt malformed = %x, %v", plaintext, err)
		}
	}
}

func TestLinuxWireBoundsAndContentTypes(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	if value, err := decryptLinuxSecret(key, bytes.Repeat([]byte{2}, 17), bytes.Repeat([]byte{3}, 16)); err == nil || value != nil {
		t.Fatalf("oversized parameters = %x, %v", value, err)
	}
	if value, err := decryptLinuxSecret(key, bytes.Repeat([]byte{2}, 16),
		bytes.Repeat([]byte{3}, MaxSecretBytes+2*aes.BlockSize)); err == nil || value != nil {
		t.Fatalf("oversized ciphertext = %x, %v", value, err)
	}
	for _, value := range []string{"text/plain", "text/plain; charset=utf-8", "TEXT/PLAIN;CHARSET=UTF8"} {
		if !allowedLinuxContentType(value) {
			t.Fatalf("rejected %q", value)
		}
	}
	for _, value := range []string{"application/octet-stream", "text/html", ""} {
		if allowedLinuxContentType(value) {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestLinuxSessionMaterialZeroization(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{7}, 16)
	private := new(big.Int).SetBytes(bytes.Repeat([]byte{8}, 32))
	public := new(big.Int).SetBytes(bytes.Repeat([]byte{9}, 32))
	zeroLinuxSessionMaterial(key, private, public)
	if !bytes.Equal(key, make([]byte, len(key))) || private.Sign() != 0 || public.Sign() != 0 {
		t.Fatal("session key material was not zeroed")
	}
}
