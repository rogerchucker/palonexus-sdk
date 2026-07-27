//go:build linux

package keystore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
	"time"

	dbus "github.com/keybase/dbus"
	"golang.org/x/crypto/hkdf"
)

const (
	secretServiceName       = "org.freedesktop.secrets"
	secretServicePath       = dbus.ObjectPath("/org/freedesktop/secrets")
	secretDefaultCollection = dbus.ObjectPath("/org/freedesktop/secrets/aliases/default")
	secretNullPrompt        = dbus.ObjectPath("/")
)

type nativeLinuxFacade struct {
	conn    *dbus.Conn
	connect func() (*dbus.Conn, error)
}

type linuxSession struct {
	path       dbus.ObjectPath
	private    *big.Int
	public     *big.Int
	aesKey     []byte
	closeCalls int
}

type linuxSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func newNativeLinuxFacade() (*nativeLinuxFacade, error) {
	return &nativeLinuxFacade{connect: func() (*dbus.Conn, error) {
		return dbus.ConnectSessionBus()
	}}, nil
}

func (f *nativeLinuxFacade) object(path dbus.ObjectPath) dbus.BusObject {
	return f.conn.Object(secretServiceName, path)
}

func (f *nativeLinuxFacade) Locked(ctx context.Context) (bool, error) {
	if f.conn == nil {
		var result bool
		err := f.withConnection(func(operation *nativeLinuxFacade) error {
			var err error
			result, err = operation.Locked(ctx)
			return err
		})
		return result, err
	}
	var value dbus.Variant
	err := f.object(secretDefaultCollection).
		CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0,
			"org.freedesktop.Secret.Collection", "Locked").
		Store(&value)
	if err != nil {
		return false, err
	}
	locked, ok := value.Value().(bool)
	if !ok {
		return false, errLinuxMalformedSecret
	}
	return locked, nil
}

func (f *nativeLinuxFacade) Put(
	ctx context.Context,
	service string,
	account string,
	value []byte,
) (bool, error) {
	if f.conn == nil {
		var prompted bool
		err := f.withConnection(func(operation *nativeLinuxFacade) error {
			var err error
			prompted, err = operation.Put(ctx, service, account, value)
			return err
		})
		return prompted, err
	}
	session, err := f.openSession(ctx)
	if err != nil {
		return false, err
	}
	defer f.closeAndZero(session)
	secret, err := session.encrypt(value)
	if err != nil {
		return false, err
	}
	defer Zero(secret.Value)
	defer Zero(secret.Parameters)
	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("PaloNexus Guard credential"),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(map[string]string{
			"service": service,
			"account": account,
		}),
	}
	var item, prompt dbus.ObjectPath
	err = f.object(secretDefaultCollection).
		CallWithContext(ctx, "org.freedesktop.Secret.Collection.CreateItem", 0,
			properties, secret, true).
		Store(&item, &prompt)
	if err != nil {
		return false, err
	}
	return prompt != secretNullPrompt, nil
}

func (f *nativeLinuxFacade) Find(
	ctx context.Context,
	service string,
	account string,
) ([]linuxItem, error) {
	if f.conn == nil {
		var result []linuxItem
		err := f.withConnection(func(operation *nativeLinuxFacade) error {
			var err error
			result, err = operation.Find(ctx, service, account)
			return err
		})
		return result, err
	}
	var paths []dbus.ObjectPath
	err := f.object(secretDefaultCollection).
		CallWithContext(ctx, "org.freedesktop.Secret.Collection.SearchItems", 0,
			map[string]string{"service": service, "account": account}).
		Store(&paths)
	if err != nil {
		return nil, err
	}
	items := make([]linuxItem, len(paths))
	for index, path := range paths {
		if !path.IsValid() {
			return nil, errLinuxMalformedSecret
		}
		items[index] = linuxItem(path)
	}
	return items, nil
}

func (f *nativeLinuxFacade) Get(ctx context.Context, item linuxItem) ([]byte, error) {
	if f.conn == nil {
		var result []byte
		err := f.withConnection(func(operation *nativeLinuxFacade) error {
			var err error
			result, err = operation.Get(ctx, item)
			return err
		})
		return result, err
	}
	path := dbus.ObjectPath(item)
	if !path.IsValid() {
		return nil, errLinuxMalformedSecret
	}
	session, err := f.openSession(ctx)
	if err != nil {
		return nil, err
	}
	defer f.closeAndZero(session)
	var wire []any
	err = f.object(path).
		CallWithContext(ctx, "org.freedesktop.Secret.Item.GetSecret", 0, session.path).
		Store(&wire)
	if err != nil {
		return nil, err
	}
	var secret linuxSecret
	if err := dbus.Store(
		wire,
		&secret.Session,
		&secret.Parameters,
		&secret.Value,
		&secret.ContentType,
	); err != nil {
		return nil, errLinuxMalformedSecret
	}
	defer Zero(secret.Parameters)
	defer Zero(secret.Value)
	if secret.Session != session.path || !allowedLinuxContentType(secret.ContentType) ||
		len(secret.Parameters) != aes.BlockSize || len(secret.Value) == 0 ||
		len(secret.Value)%aes.BlockSize != 0 || len(secret.Value) > MaxSecretBytes+aes.BlockSize {
		return nil, errLinuxMalformedSecret
	}
	return session.decrypt(secret)
}

func (f *nativeLinuxFacade) Delete(ctx context.Context, item linuxItem) (bool, error) {
	if f.conn == nil {
		var prompted bool
		err := f.withConnection(func(operation *nativeLinuxFacade) error {
			var err error
			prompted, err = operation.Delete(ctx, item)
			return err
		})
		return prompted, err
	}
	path := dbus.ObjectPath(item)
	if !path.IsValid() {
		return false, errLinuxMalformedSecret
	}
	var prompt dbus.ObjectPath
	err := f.object(path).
		CallWithContext(ctx, "org.freedesktop.Secret.Item.Delete", 0).
		Store(&prompt)
	if err != nil {
		return false, err
	}
	return prompt != secretNullPrompt, nil
}

func (f *nativeLinuxFacade) withConnection(operation func(*nativeLinuxFacade) error) error {
	if f.connect == nil {
		return errLinuxMalformedSecret
	}
	conn, err := f.connect()
	if err != nil {
		return err
	}
	defer conn.Close()
	return operation(&nativeLinuxFacade{conn: conn})
}

func (f *nativeLinuxFacade) openSession(ctx context.Context) (*linuxSession, error) {
	group := oakleyGroup()
	private, public, err := group.keypair()
	if err != nil {
		return nil, err
	}
	session := &linuxSession{private: private, public: public}
	ok := false
	defer func() {
		if !ok {
			session.zero()
		}
	}()
	var output dbus.Variant
	err = f.object(secretServicePath).
		CallWithContext(ctx, "org.freedesktop.Secret.Service.OpenSession", 0,
			"dh-ietf1024-sha256-aes128-cbc-pkcs7", dbus.MakeVariant(public.Bytes())).
		Store(&output, &session.path)
	if err != nil {
		return nil, err
	}
	theirPublicBytes, valid := output.Value().([]byte)
	if !valid || !session.path.IsValid() || session.path == secretNullPrompt {
		return nil, errLinuxMalformedSecret
	}
	theirPublic := new(big.Int).SetBytes(theirPublicBytes)
	defer zeroLinuxBigInt(theirPublic)
	session.aesKey, err = group.derive(theirPublic, private)
	if err != nil {
		return nil, err
	}
	ok = true
	return session, nil
}

func (f *nativeLinuxFacade) closeAndZero(session *linuxSession) {
	if session == nil {
		return
	}
	defer session.zero()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = f.object(session.path).
		CallWithContext(ctx, "org.freedesktop.Secret.Session.Close", 0).Err
	session.closeCalls++
}

func (s *linuxSession) encrypt(plaintext []byte) (linuxSecret, error) {
	block, err := aes.NewCipher(s.aesKey)
	if err != nil {
		return linuxSecret{}, err
	}
	padded := padPKCS7(plaintext, aes.BlockSize)
	defer Zero(padded)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(cryptorand.Reader, iv); err != nil {
		return linuxSecret{}, err
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return linuxSecret{
		Session:     s.path,
		Parameters:  iv,
		Value:       ciphertext,
		ContentType: "text/plain",
	}, nil
}

func (s *linuxSession) decrypt(secret linuxSecret) ([]byte, error) {
	return decryptLinuxSecret(s.aesKey, secret.Parameters, secret.Value)
}

func (s *linuxSession) zero() {
	zeroLinuxSessionMaterial(s.aesKey, s.private, s.public)
	s.aesKey = nil
	s.private = nil
	s.public = nil
	s.path = ""
}

type dhGroup struct {
	g       *big.Int
	p       *big.Int
	pMinus1 *big.Int
}

func oakleyGroup() dhGroup {
	p, _ := new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
		16,
	)
	return dhGroup{
		g:       big.NewInt(2),
		p:       p,
		pMinus1: new(big.Int).Sub(new(big.Int).Set(p), big.NewInt(1)),
	}
}

func (g dhGroup) keypair() (*big.Int, *big.Int, error) {
	for {
		private, err := cryptorand.Int(cryptorand.Reader, g.pMinus1)
		if err != nil {
			return nil, nil, err
		}
		if private.Sign() > 0 {
			public := new(big.Int).Exp(g.g, private, g.p)
			return private, public, nil
		}
	}
}

func (g dhGroup) derive(theirPublic, private *big.Int) ([]byte, error) {
	one := big.NewInt(1)
	if theirPublic.Cmp(one) <= 0 || theirPublic.Cmp(g.pMinus1) >= 0 {
		return nil, errLinuxMalformedSecret
	}
	shared := new(big.Int).Exp(theirPublic, private, g.p)
	defer zeroLinuxBigInt(shared)
	sharedBytes := shared.Bytes()
	defer Zero(sharedBytes)
	pseudorandomKey := hkdf.Extract(sha256.New, sharedBytes, nil)
	defer Zero(pseudorandomKey)
	reader := hkdf.Expand(sha256.New, pseudorandomKey, nil)
	key := make([]byte, 16)
	if _, err := io.ReadFull(reader, key); err != nil {
		Zero(key)
		return nil, err
	}
	return key, nil
}

func padPKCS7(input []byte, size int) []byte {
	padding := size - len(input)%size
	return append(append([]byte(nil), input...), bytes.Repeat([]byte{byte(padding)}, padding)...)
}
