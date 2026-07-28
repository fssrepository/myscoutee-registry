package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

type SigningKey struct {
	privateKey       ed25519.PrivateKey
	publicKey        ed25519.PublicKey
	publicKeyDER     []byte
	encodedPublicKey string
	fingerprint      string
	keyID            string
}

func Load(path string) (*SigningKey, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read registry signing key: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("registry signing key path must not be a symbolic link")
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("registry signing key path must be a regular file")
	}
	if pathInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("registry signing key must not be accessible by group or other users")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open registry signing key: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened registry signing key: %w", err)
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return nil, errors.New("registry signing key was replaced while being opened")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil {
		return nil, fmt.Errorf("read registry signing key: %w", err)
	}
	if len(contents) > 64*1024 {
		return nil, errors.New("registry signing key file is unexpectedly large")
	}
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("registry signing key must be one PKCS#8 PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse registry signing key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("registry signing key is not Ed25519")
	}
	return fromPrivateKey(privateKey)
}

func LoadOrGenerate(path string, allowGenerate bool) (*SigningKey, bool, error) {
	key, err := Load(path)
	if err == nil {
		return key, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	if !allowGenerate {
		return nil, false, fmt.Errorf("registry signing key is absent at %s and first-run generation is disabled", path)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generate Ed25519 registry signing key: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, false, fmt.Errorf("marshal registry signing key: %w", err)
	}
	contents := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if len(contents) == 0 {
		return nil, false, errors.New("encode registry signing key")
	}
	if err := writeAtomicallyIfAbsent(path, contents); err != nil {
		if errors.Is(err, os.ErrExist) {
			key, loadErr := Load(path)
			return key, false, loadErr
		}
		return nil, false, err
	}
	key, err = fromPrivateKey(privateKey)
	if err != nil {
		return nil, false, err
	}
	if !key.publicKey.Equal(publicKey) {
		return nil, false, errors.New("generated registry public key mismatch")
	}
	return key, true, nil
}

func fromPrivateKey(privateKey ed25519.PrivateKey) (*SigningKey, error) {
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("derive Ed25519 public key")
	}
	encoded, der, err := protocol.EncodePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return &SigningKey{
		privateKey:       append(ed25519.PrivateKey(nil), privateKey...),
		publicKey:        append(ed25519.PublicKey(nil), publicKey...),
		publicKeyDER:     append([]byte(nil), der...),
		encodedPublicKey: encoded,
		fingerprint:      protocol.PublicKeyFingerprint(der),
		keyID:            protocol.RegistryKeyID(der),
	}, nil
}

func (key *SigningKey) Sign(message []byte) []byte {
	return ed25519.Sign(key.privateKey, message)
}

func (key *SigningKey) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), key.publicKey...)
}

func (key *SigningKey) PublicKeyDER() []byte {
	return append([]byte(nil), key.publicKeyDER...)
}

func (key *SigningKey) EncodedPublicKey() string {
	return key.encodedPublicKey
}

func (key *SigningKey) Fingerprint() string {
	return key.fingerprint
}

func (key *SigningKey) KeyID() string {
	return key.keyID
}

func writeAtomicallyIfAbsent(path string, contents []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create registry signing-key directory: %w", err)
	}
	temp, err := os.CreateTemp(directory, ".registry-signing-key-*")
	if err != nil {
		return fmt.Errorf("create temporary registry signing key: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("restrict temporary registry signing key: %w", err)
	}
	if _, err := temp.Write(contents); err != nil {
		temp.Close()
		return fmt.Errorf("write temporary registry signing key: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync temporary registry signing key: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary registry signing key: %w", err)
	}

	if err := os.Link(tempPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return os.ErrExist
		}
		return fmt.Errorf("publish registry signing key atomically: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open registry signing-key directory for durability sync: %w", err)
	}
	if err := directoryHandle.Sync(); err != nil {
		_ = directoryHandle.Close()
		return fmt.Errorf("sync registry signing-key directory: %w", err)
	}
	if err := directoryHandle.Close(); err != nil {
		return fmt.Errorf("close registry signing-key directory: %w", err)
	}
	return nil
}
