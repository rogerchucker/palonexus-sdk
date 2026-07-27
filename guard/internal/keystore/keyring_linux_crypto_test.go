package keystore

import (
	"bytes"
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
