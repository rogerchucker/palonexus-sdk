package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"math/big"
	"strings"
)

func allowedLinuxContentType(value string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), " ", ""))
	switch normalized {
	case "text/plain", "text/plain;charset=utf-8", "text/plain;charset=utf8", "text/plain;charset=us-ascii":
		return true
	default:
		return false
	}
}

func decryptLinuxSecret(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil || len(iv) != aes.BlockSize || len(ciphertext) < aes.BlockSize ||
		len(ciphertext)%aes.BlockSize != 0 || len(ciphertext) > MaxSecretBytes+aes.BlockSize {
		return nil, errLinuxMalformedSecret
	}
	padded := append([]byte(nil), ciphertext...)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, padded)
	plaintext, err := unpadLinuxPKCS7(padded, aes.BlockSize)
	if err != nil {
		Zero(padded)
		return nil, errLinuxMalformedSecret
	}
	result := append([]byte(nil), plaintext...)
	Zero(padded)
	if len(result) == 0 || len(result) > MaxSecretBytes {
		Zero(result)
		return nil, errLinuxMalformedSecret
	}
	return result, nil
}

func unpadLinuxPKCS7(input []byte, size int) ([]byte, error) {
	if len(input) == 0 || len(input)%size != 0 {
		return nil, errLinuxMalformedSecret
	}
	padding := int(input[len(input)-1])
	if padding == 0 || padding > size || padding > len(input) {
		return nil, errLinuxMalformedSecret
	}
	for _, value := range input[len(input)-padding:] {
		if int(value) != padding {
			return nil, errLinuxMalformedSecret
		}
	}
	return input[:len(input)-padding], nil
}

func zeroLinuxSessionMaterial(key []byte, private, public *big.Int) {
	Zero(key)
	zeroLinuxBigInt(private)
	zeroLinuxBigInt(public)
}

func zeroLinuxBigInt(value *big.Int) {
	if value == nil {
		return
	}
	words := value.Bits()
	for index := range words {
		words[index] = 0
	}
	value.SetInt64(0)
}
