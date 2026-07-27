package keystore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"
)

type encryptedFiles interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
	Close() error
}

const encryptedDocumentVersionBytes = 1

type encryptedFileBackend struct {
	aead   cipher.AEAD
	files  encryptedFiles
	key    []byte
	mu     sync.Mutex
	closed bool
}

func (b *encryptedFileBackend) maxDocumentBytes() int {
	return encryptedDocumentVersionBytes + b.aead.NonceSize() + MaxSecretBytes + b.aead.Overhead()
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
	files, err := newEncryptedFiles(options.Root)
	if err != nil {
		return nil, err
	}
	return &encryptedFileBackend{aead: aead, files: files, key: append([]byte(nil), options.Key...)}, nil
}

func (b *encryptedFileBackend) Put(ctx context.Context, service, account string, secret []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return ErrUnavailable
	}
	aad := []byte(service + "\x00" + account)
	ciphertext := b.aead.Seal(nil, nonce, secret, aad)
	document := append(append([]byte{1}, nonce...), ciphertext...)
	defer Zero(document)
	return b.files.Put(ctx, encryptedName(service, account), document)
}

func (b *encryptedFileBackend) Get(ctx context.Context, service, account string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrUnavailable
	}
	document, err := b.files.Get(ctx, encryptedName(service, account))
	if err != nil {
		return nil, err
	}
	defer Zero(document)
	if len(document) > b.maxDocumentBytes() {
		return nil, ErrUnavailable
	}
	if len(document) < 1+b.aead.NonceSize() || document[0] != 1 {
		return nil, ErrUnavailable
	}
	nonce := document[1 : 1+b.aead.NonceSize()]
	value, err := b.aead.Open(
		nil,
		nonce,
		document[1+b.aead.NonceSize():],
		[]byte(service+"\x00"+account),
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	return value, nil
}

func (b *encryptedFileBackend) Delete(ctx context.Context, service, account string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrUnavailable
	}
	return b.files.Delete(ctx, encryptedName(service, account))
}

func (b *encryptedFileBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	Zero(b.key)
	b.key = nil
	b.aead = nil
	return b.files.Close()
}

func encryptedName(service, account string) string {
	sum := sha256.Sum256([]byte("palonexus-test-credential-v1\x00" + service + "\x00" + account))
	return "credential-" + stringHex(sum[:]) + ".enc"
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
