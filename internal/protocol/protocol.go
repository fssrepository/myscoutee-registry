package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	Version = "1"

	RegistrationPath = "/v1/deployments/register"
	BatchPath        = "/v1/mau/batches"
	IdentityPath     = "/v1/registry/identity"

	KeyAlgorithmEd25519 = "Ed25519"

	InstallationTestKind    = "installation-test"
	InstallationTestRuleset = "installation-test-v1"
	InstallationEntryType   = "INSTALLATION_TEST_BATCH_ACCEPTED"

	ZeroHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	ErrInvalidPublicKey = errors.New("invalid Ed25519 SPKI public key")
	ErrInvalidSignature = errors.New("invalid Ed25519 signature encoding")
)

type RegistrationRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	RegistryScope   string `json:"registry_scope"`
	Timestamp       string `json:"timestamp"`
	Nonce           string `json:"nonce"`
	IdempotencyKey  string `json:"idempotency_key"`
	KeyAlgorithm    string `json:"key_algorithm"`
	PublicKey       string `json:"public_key"`
	SoftwareVersion string `json:"software_version"`
	PayloadHash     string `json:"payload_hash"`
	Signature       string `json:"signature"`
}

type RegistryIdentity struct {
	ProtocolVersion   string `json:"protocol_version"`
	RegistryScope     string `json:"registry_scope"`
	RegistryKeyID     string `json:"registry_key_id"`
	RegistryPublicKey string `json:"registry_public_key"`
	Signature         string `json:"signature"`
}

type RegistrationResponse struct {
	ProtocolVersion      string `json:"protocol_version"`
	RegistryScope        string `json:"registry_scope"`
	DeploymentID         string `json:"deployment_id"`
	RegisteredAt         string `json:"registered_at"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	RegistryKeyID        string `json:"registry_key_id"`
	RegistryPublicKey    string `json:"registry_public_key"`
	ReceiptSignature     string `json:"receipt_signature"`
	Duplicate            bool   `json:"duplicate"`
}

type BatchRequest struct {
	ProtocolVersion   string `json:"protocol_version"`
	RegistryScope     string `json:"registry_scope"`
	DeploymentID      string `json:"deployment_id"`
	Timestamp         string `json:"timestamp"`
	Nonce             string `json:"nonce"`
	IdempotencyKey    string `json:"idempotency_key"`
	Kind              string `json:"kind"`
	Period            string `json:"period"`
	RulesetVersion    string `json:"ruleset_version"`
	QualifiedMAUCount int64  `json:"qualified_mau_count"`
	CommitmentHash    string `json:"commitment_hash"`
	PayloadHash       string `json:"payload_hash"`
	Signature         string `json:"signature"`
}

type MAUReceipt struct {
	LedgerIndex       int64  `json:"ledger_index"`
	EntryHash         string `json:"entry_hash"`
	PreviousEntryHash string `json:"previous_entry_hash"`
	BatchHash         string `json:"batch_hash"`
	Kind              string `json:"kind"`
	Period            string `json:"period"`
	RulesetVersion    string `json:"ruleset_version"`
	QualifiedMAUCount int64  `json:"qualified_mau_count"`
	AcceptedAt        string `json:"accepted_at"`
	CheckpointDate    string `json:"checkpoint_date"`
	RegistryScope     string `json:"registry_scope"`
	RegistryKeyID     string `json:"registry_key_id"`
	RegistryPublicKey string `json:"registry_public_key"`
	Signature         string `json:"signature"`
}

type BatchResponse struct {
	ProtocolVersion string     `json:"protocol_version"`
	RegistryScope   string     `json:"registry_scope"`
	BatchID         string     `json:"batch_id"`
	DeploymentID    string     `json:"deployment_id"`
	IdempotencyKey  string     `json:"idempotency_key"`
	Duplicate       bool       `json:"duplicate"`
	Receipt         MAUReceipt `json:"receipt"`
}

type LedgerEntry struct {
	ProtocolVersion   string
	RegistryScope     string
	LedgerIndex       int64
	EntryType         string
	DeploymentID      string
	BatchID           string
	Kind              string
	Period            string
	RulesetVersion    string
	QualifiedMAUCount int64
	BatchHash         string
	PreviousEntryHash string
	EntryHash         string
	AcceptedAt        string
}

type Checkpoint struct {
	RegistryScope          string `json:"registry_scope"`
	CheckpointDate         string `json:"checkpoint_date"`
	ThroughLedgerIndex     int64  `json:"through_ledger_index"`
	EntryCount             int64  `json:"entry_count"`
	LedgerHeadHash         string `json:"ledger_head_hash"`
	PreviousCheckpointHash string `json:"previous_checkpoint_hash"`
	CheckpointHash         string `json:"checkpoint_hash"`
	GeneratedAt            string `json:"generated_at"`
	RegistryKeyID          string `json:"registry_key_id"`
	RegistryPublicKey      string `json:"registry_public_key"`
	Signature              string `json:"signature"`
}

func CanonicalRequest(
	method string,
	path string,
	protocolVersion string,
	registryScope string,
	signer string,
	timestamp string,
	nonce string,
	idempotencyKey string,
	payloadHash string,
) []byte {
	return canonical(
		"myscoutee-registry-request-v1",
		strings.ToUpper(method),
		path,
		protocolVersion,
		registryScope,
		signer,
		timestamp,
		nonce,
		idempotencyKey,
		payloadHash,
	)
}

func RegistryIdentityMessage(
	protocolVersion string,
	registryScope string,
	registryKeyID string,
	registryPublicKey string,
) []byte {
	return canonical(
		"myscoutee-registry-identity-v1",
		protocolVersion,
		registryScope,
		registryKeyID,
		registryPublicKey,
	)
}

func RegistrationPayload(keyAlgorithm, publicKey, softwareVersion string) []byte {
	return canonical(
		"myscoutee-registry-registration-payload-v1",
		keyAlgorithm,
		publicKey,
		softwareVersion,
	)
}

func RegistrationReceipt(
	protocolVersion string,
	registryScope string,
	deploymentID string,
	publicKeyFingerprint string,
	registeredAt string,
	registryKeyID string,
) []byte {
	return canonical(
		"myscoutee-registry-registration-receipt-v1",
		protocolVersion,
		registryScope,
		deploymentID,
		publicKeyFingerprint,
		registeredAt,
		registryKeyID,
	)
}

func InstallationTestCommitment(deploymentID, idempotencyKey string) []byte {
	return canonical(
		"myscoutee-registry-installation-test-v1",
		deploymentID,
		idempotencyKey,
	)
}

func BatchPayload(
	kind string,
	period string,
	rulesetVersion string,
	qualifiedMAUCount int64,
	commitmentHash string,
) []byte {
	return canonical(
		"myscoutee-registry-mau-batch-payload-v1",
		kind,
		period,
		rulesetVersion,
		strconv.FormatInt(qualifiedMAUCount, 10),
		commitmentHash,
	)
}

func LedgerEntryMessage(entry LedgerEntry) []byte {
	return canonical(
		"myscoutee-registry-ledger-entry-v1",
		entry.ProtocolVersion,
		entry.RegistryScope,
		strconv.FormatInt(entry.LedgerIndex, 10),
		entry.EntryType,
		entry.DeploymentID,
		entry.BatchID,
		entry.Kind,
		entry.Period,
		entry.RulesetVersion,
		strconv.FormatInt(entry.QualifiedMAUCount, 10),
		entry.BatchHash,
		entry.PreviousEntryHash,
		entry.AcceptedAt,
	)
}

func MAUReceiptMessage(
	protocolVersion string,
	registryScope string,
	batchID string,
	deploymentID string,
	ledgerIndex int64,
	entryHash string,
	previousEntryHash string,
	batchHash string,
	kind string,
	period string,
	rulesetVersion string,
	qualifiedMAUCount int64,
	acceptedAt string,
	checkpointDate string,
	registryKeyID string,
) []byte {
	return canonical(
		"myscoutee-registry-mau-receipt-v1",
		protocolVersion,
		registryScope,
		batchID,
		deploymentID,
		strconv.FormatInt(ledgerIndex, 10),
		entryHash,
		previousEntryHash,
		batchHash,
		kind,
		period,
		rulesetVersion,
		strconv.FormatInt(qualifiedMAUCount, 10),
		acceptedAt,
		checkpointDate,
		registryKeyID,
	)
}

func CheckpointMessage(checkpoint Checkpoint) []byte {
	return canonical(
		"myscoutee-registry-checkpoint-v1",
		checkpoint.RegistryScope,
		checkpoint.CheckpointDate,
		strconv.FormatInt(checkpoint.ThroughLedgerIndex, 10),
		strconv.FormatInt(checkpoint.EntryCount, 10),
		checkpoint.LedgerHeadHash,
		checkpoint.PreviousCheckpointHash,
		checkpoint.GeneratedAt,
		checkpoint.RegistryKeyID,
	)
}

func Digest(message []byte) string {
	sum := sha256.Sum256(message)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func IsDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func IsRegistryScope(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for index, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == ':' || character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func PublicKeyFingerprint(spkiDER []byte) string {
	return Digest(spkiDER)
}

func RegistryKeyID(spkiDER []byte) string {
	fingerprint := PublicKeyFingerprint(spkiDER)
	return "rkey_" + fingerprint[len("sha256:"):len("sha256:")+32]
}

func ParsePublicKey(encoded string) (ed25519.PublicKey, []byte, error) {
	der, err := decodeCanonicalBase64(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, ErrInvalidPublicKey
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || !bytes.Equal(canonicalDER, der) {
		return nil, nil, ErrInvalidPublicKey
	}
	return publicKey, der, nil
}

func EncodePublicKey(publicKey ed25519.PublicKey) (string, []byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", nil, fmt.Errorf("marshal Ed25519 public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), der, nil
}

func ParseSignature(encoded string) ([]byte, error) {
	signature, err := decodeCanonicalBase64(encoded)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalidSignature
	}
	return signature, nil
}

func EncodeSignature(signature []byte) string {
	return base64.StdEncoding.EncodeToString(signature)
}

func Verify(publicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

func HasCanonicalLineBreak(value string) bool {
	return strings.ContainsAny(value, "\r\n")
}

func canonical(lines ...string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

func decodeCanonicalBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("base64 value is not canonical padded RFC 4648 encoding")
	}
	return decoded, nil
}
