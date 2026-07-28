//go:build !darwin && !linux

package keystore

func newEncryptedFiles(string) (encryptedFiles, error) { return nil, ErrUnsupported }
