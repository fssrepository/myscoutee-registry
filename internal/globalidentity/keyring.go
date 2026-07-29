package globalidentity

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cloudflare/circl/oprf"
)

const (
	SuiteName = "P256-SHA256"
	ModeName  = "VOPRF"

	keySeedSize = 32
)

var deriveInfo = []byte("myscoutee-global-identity-v1")

type PublicKey struct {
	Version     int64
	Suite       string
	PublicKey   []byte
	ActivatedAt string
	Active      bool
}

type KeyRing struct {
	activeVersion int64
	keys          map[int64]*keyVersion
}

type keyVersion struct {
	public     PublicKey
	privateKey *oprf.PrivateKey
}

type persistedKeyRing struct {
	ActiveVersion int64          `json:"active_version"`
	Keys          []persistedKey `json:"keys"`
}

type persistedKey struct {
	Version     int64  `json:"version"`
	Seed        string `json:"seed"`
	ActivatedAt string `json:"activated_at"`
}

func LoadOrGenerate(
	path string,
	allowGenerate bool,
	now func() time.Time,
) (*KeyRing, bool, error) {
	ring, err := Load(path)
	if err == nil {
		return ring, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	if !allowGenerate {
		return nil, false, fmt.Errorf(
			"global identity VOPRF keyring is absent at %s and generation is disabled",
			path,
		)
	}
	if now == nil {
		now = time.Now
	}
	seed := make([]byte, keySeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, false, fmt.Errorf("generate global identity VOPRF seed: %w", err)
	}
	persisted := persistedKeyRing{
		ActiveVersion: 1,
		Keys: []persistedKey{{
			Version:     1,
			Seed:        base64.StdEncoding.EncodeToString(seed),
			ActivatedAt: now().UTC().Truncate(time.Second).Format(time.RFC3339),
		}},
	}
	clearBytes(seed)
	if err := writeKeyRing(path, persisted, true); err != nil {
		if errors.Is(err, os.ErrExist) {
			ring, loadErr := Load(path)
			return ring, false, loadErr
		}
		return nil, false, err
	}
	ring, err = parseKeyRing(persisted)
	if err != nil {
		return nil, false, err
	}
	return ring, true, nil
}

func Load(path string) (*KeyRing, error) {
	persisted, err := readPersistedKeyRing(path)
	if err != nil {
		return nil, err
	}
	return parseKeyRing(persisted)
}

func readPersistedKeyRing(path string) (persistedKeyRing, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return persistedKeyRing{},
			fmt.Errorf("read global identity VOPRF keyring: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return persistedKeyRing{}, errors.New(
			"global identity VOPRF keyring must be a regular non-symlink file",
		)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return persistedKeyRing{}, errors.New(
			"global identity VOPRF keyring must not be accessible by group or other users",
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return persistedKeyRing{},
			fmt.Errorf("open global identity VOPRF keyring: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return persistedKeyRing{},
			fmt.Errorf("stat global identity VOPRF keyring: %w", err)
	}
	if !os.SameFile(info, opened) {
		return persistedKeyRing{}, errors.New(
			"global identity VOPRF keyring was replaced while being opened",
		)
	}
	contents, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil {
		return persistedKeyRing{},
			fmt.Errorf("read global identity VOPRF keyring: %w", err)
	}
	if len(contents) > 64*1024 {
		return persistedKeyRing{},
			errors.New("global identity VOPRF keyring is unexpectedly large")
	}
	var persisted persistedKeyRing
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&persisted); err != nil {
		return persistedKeyRing{},
			fmt.Errorf("decode global identity VOPRF keyring: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return persistedKeyRing{}, errors.New(
			"global identity VOPRF keyring must contain one JSON object",
		)
	}
	return persisted, nil
}

// Rotate appends a fresh key version and atomically changes the active
// version. Older key versions remain available so deployments can evaluate
// both old and new commitments during an explicit correction.
func Rotate(path string, now func() time.Time) (PublicKey, error) {
	persisted, err := readPersistedKeyRing(path)
	if err != nil {
		return PublicKey{}, err
	}
	ring, err := parseKeyRing(persisted)
	if err != nil {
		return PublicKey{}, err
	}
	if now == nil {
		now = time.Now
	}
	versions := ring.PublicKeys()
	nextVersion := versions[len(versions)-1].Version + 1
	seed := make([]byte, keySeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return PublicKey{}, fmt.Errorf("generate rotated VOPRF seed: %w", err)
	}
	activatedAt := now().UTC().Truncate(time.Second).Format(time.RFC3339)
	persisted.ActiveVersion = nextVersion
	persisted.Keys = append(persisted.Keys, persistedKey{
		Version:     nextVersion,
		Seed:        base64.StdEncoding.EncodeToString(seed),
		ActivatedAt: activatedAt,
	})
	clearBytes(seed)
	if err := writeKeyRing(path, persisted, false); err != nil {
		return PublicKey{}, err
	}
	rotated, err := Load(path)
	if err != nil {
		return PublicKey{}, err
	}
	key, ok := rotated.PublicKey(nextVersion)
	if !ok {
		return PublicKey{}, errors.New("rotated VOPRF key is unavailable")
	}
	return key, nil
}

func (ring *KeyRing) ActivePublicKey() PublicKey {
	key := ring.keys[ring.activeVersion]
	result := key.public
	result.PublicKey = append([]byte(nil), result.PublicKey...)
	return result
}

func (ring *KeyRing) PublicKey(version int64) (PublicKey, bool) {
	key, ok := ring.keys[version]
	if !ok {
		return PublicKey{}, false
	}
	result := key.public
	result.PublicKey = append([]byte(nil), result.PublicKey...)
	return result, true
}

func (ring *KeyRing) PublicKeys() []PublicKey {
	keys := make([]PublicKey, 0, len(ring.keys))
	for _, key := range ring.keys {
		public := key.public
		public.PublicKey = append([]byte(nil), public.PublicKey...)
		keys = append(keys, public)
	}
	sort.Slice(keys, func(left, right int) bool {
		return keys[left].Version < keys[right].Version
	})
	return keys
}

func (ring *KeyRing) Evaluate(
	version int64,
	blindedElement []byte,
) (publicKey []byte, evaluatedElement []byte, proof []byte, err error) {
	key, ok := ring.keys[version]
	if !ok {
		return nil, nil, nil, errors.New("global identity VOPRF key version is unavailable")
	}
	suite := oprf.SuiteP256
	element := suite.Group().NewElement()
	if err := element.UnmarshalBinary(blindedElement); err != nil ||
		element.IsIdentity() {
		return nil, nil, nil, errors.New("blinded VOPRF element is invalid")
	}
	server := oprf.NewVerifiableServer(suite, key.privateKey)
	evaluation, err := server.Evaluate(&oprf.EvaluationRequest{
		Elements: []oprf.Blinded{element},
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("evaluate blinded VOPRF element: %w", err)
	}
	if len(evaluation.Elements) != 1 || evaluation.Proof == nil {
		return nil, nil, nil, errors.New("VOPRF evaluation result is incomplete")
	}
	evaluated, err := evaluation.Elements[0].MarshalBinaryCompress()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode evaluated VOPRF element: %w", err)
	}
	encodedProof, err := evaluation.Proof.MarshalBinary()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode VOPRF DLEQ proof: %w", err)
	}
	if len(key.public.PublicKey) != 33 ||
		len(evaluated) != 33 ||
		len(encodedProof) != 64 {
		return nil, nil, nil,
			errors.New("VOPRF evaluation has a non-canonical encoded length")
	}
	return append([]byte(nil), key.public.PublicKey...),
		evaluated,
		encodedProof,
		nil
}

func parseKeyRing(persisted persistedKeyRing) (*KeyRing, error) {
	if persisted.ActiveVersion < 1 || len(persisted.Keys) == 0 {
		return nil, errors.New("global identity VOPRF keyring is empty")
	}
	ring := &KeyRing{
		activeVersion: persisted.ActiveVersion,
		keys:          make(map[int64]*keyVersion, len(persisted.Keys)),
	}
	for index, item := range persisted.Keys {
		if item.Version != int64(index+1) {
			return nil, errors.New(
				"global identity VOPRF key versions must be consecutive from one",
			)
		}
		if _, err := time.Parse(time.RFC3339, item.ActivatedAt); err != nil {
			return nil, errors.New(
				"global identity VOPRF key has an invalid activated_at",
			)
		}
		seed, err := base64.StdEncoding.Strict().DecodeString(item.Seed)
		if err != nil || len(seed) != keySeedSize ||
			base64.StdEncoding.EncodeToString(seed) != item.Seed {
			return nil, errors.New(
				"global identity VOPRF seed must be canonical padded base64",
			)
		}
		privateKey, err := oprf.DeriveKey(
			oprf.SuiteP256,
			oprf.VerifiableMode,
			seed,
			deriveInfo,
		)
		clearBytes(seed)
		if err != nil {
			return nil, fmt.Errorf("derive global identity VOPRF key %d: %w", item.Version, err)
		}
		publicKey, err := privateKey.Public().MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("encode global identity VOPRF public key %d: %w", item.Version, err)
		}
		if len(publicKey) != 33 {
			return nil, errors.New(
				"global identity VOPRF public key is not compressed SEC1",
			)
		}
		ring.keys[item.Version] = &keyVersion{
			privateKey: privateKey,
			public: PublicKey{
				Version:     item.Version,
				Suite:       SuiteName,
				PublicKey:   publicKey,
				ActivatedAt: item.ActivatedAt,
				Active:      item.Version == persisted.ActiveVersion,
			},
		}
	}
	if _, ok := ring.keys[persisted.ActiveVersion]; !ok {
		return nil, errors.New("active global identity VOPRF key is missing")
	}
	return ring, nil
}

func writeKeyRing(path string, persisted persistedKeyRing, exclusive bool) error {
	contents, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return fmt.Errorf("encode global identity VOPRF keyring: %w", err)
	}
	contents = append(contents, '\n')
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create global identity VOPRF key directory: %w", err)
	}
	temp, err := os.CreateTemp(directory, ".global-identity-voprf-*")
	if err != nil {
		return fmt.Errorf("create temporary VOPRF keyring: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("restrict temporary VOPRF keyring: %w", err)
	}
	if _, err := temp.Write(contents); err != nil {
		temp.Close()
		return fmt.Errorf("write temporary VOPRF keyring: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync temporary VOPRF keyring: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary VOPRF keyring: %w", err)
	}
	if exclusive {
		if err := os.Link(tempPath, path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return os.ErrExist
			}
			return fmt.Errorf("publish VOPRF keyring: %w", err)
		}
	} else {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect VOPRF keyring before rotation: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
			info.Mode().Perm()&0o077 != 0 {
			return errors.New("existing VOPRF keyring is not a secure regular file")
		}
		if err := os.Rename(tempPath, path); err != nil {
			return fmt.Errorf("publish rotated VOPRF keyring: %w", err)
		}
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open VOPRF keyring directory: %w", err)
	}
	if err := directoryHandle.Sync(); err != nil {
		directoryHandle.Close()
		return fmt.Errorf("sync VOPRF keyring directory: %w", err)
	}
	return directoryHandle.Close()
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
