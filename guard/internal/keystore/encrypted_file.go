package keystore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type encryptedFileBackend struct {
	root string
	aead cipher.AEAD
	mu   sync.Mutex
}

func newEncryptedFileBackend(options EncryptedFileOptions) (Backend, error) {
	if len(options.Key) != 32 || options.Root == "" {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(options.Key)
	if err != nil {
		return nil, ErrInvalidKey
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := secureTestingDirectory(options.Root); err != nil {
		return nil, err
	}
	return &encryptedFileBackend{root: options.Root, aead: aead}, nil
}

func (b *encryptedFileBackend) Put(ctx context.Context, service, account string, secret []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return ErrUnavailable
	}
	aad := []byte(service + "\x00" + account)
	ciphertext := b.aead.Seal(nil, nonce, secret, aad)
	document := append(append([]byte{1}, nonce...), ciphertext...)
	defer Zero(document)
	path := b.path(service, account)
	if err := rejectSymlink(path); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(b.root, ".credential-*")
	if err != nil {
		return ErrUnavailable
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return ErrUnavailable
	}
	if _, err := temporary.Write(document); err != nil {
		temporary.Close()
		return ErrUnavailable
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return ErrUnavailable
	}
	if err := temporary.Close(); err != nil {
		return ErrUnavailable
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return ErrUnavailable
	}
	return syncDirectory(b.root)
}

func (b *encryptedFileBackend) Get(ctx context.Context, service, account string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	path := b.path(service, account)
	if err := rejectSymlink(path); err != nil {
		return nil, err
	}
	document, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil || len(document) < 1+b.aead.NonceSize() || document[0] != 1 {
		return nil, ErrUnavailable
	}
	defer Zero(document)
	nonce := document[1 : 1+b.aead.NonceSize()]
	value, err := b.aead.Open(nil, nonce, document[1+b.aead.NonceSize():], []byte(service+"\x00"+account))
	if err != nil {
		return nil, ErrUnavailable
	}
	return value, nil
}

func (b *encryptedFileBackend) Delete(ctx context.Context, service, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	path := b.path(service, account)
	if err := rejectSymlink(path); err != nil {
		return err
	}
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrUnavailable
	}
	return syncDirectory(b.root)
}

func (b *encryptedFileBackend) path(service, account string) string {
	sum := sha256.Sum256([]byte(service + "\x00" + account))
	return filepath.Join(b.root, "credential-"+stringHex(sum[:])+".enc")
}

func secureTestingDirectory(root string) error {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return ErrUnavailable
		}
		info, err = os.Lstat(root)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrUnavailable
	}
	if info.Mode().Perm() != 0o700 {
		return ErrUnavailable
	}
	return nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return ErrUnavailable
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return ErrUnavailable
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func stringHex(input []byte) string {
	const alphabet = "0123456789abcdef"
	output := make([]byte, len(input)*2)
	for index, value := range input {
		output[index*2] = alphabet[value>>4]
		output[index*2+1] = alphabet[value&15]
	}
	return string(output)
}
