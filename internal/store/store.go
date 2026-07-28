package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

var (
	ErrNotFound                 = errors.New("record not found")
	ErrIdempotencyConflict      = errors.New("idempotency key was already used with a different payload")
	ErrReplayConflict           = errors.New("nonce was already used by a different request")
	ErrInconsistentState        = errors.New("registry database contains inconsistent state")
	ErrRegistryKeyMismatch      = errors.New("configured registry signing key does not match persisted registry identity")
	ErrAcceptedAtFinalized      = errors.New("accepted_at would alter an already finalized checkpoint")
	ErrAcceptedAtBeforeHead     = errors.New("accepted_at is before the current ledger head")
	ErrAcceptedAtBeforeIdentity = errors.New("accepted_at is before registry identity creation")
)

type RegistryIdentity struct {
	ProtocolVersion string
	RegistryScope   string
	RegistryKeyID   string
	PublicKeyDER    []byte
	CreatedAt       string
}

type Deployment struct {
	DeploymentID               string
	PublicKeyDER               []byte
	PublicKeyFingerprint       string
	KeyAlgorithm               string
	SoftwareVersion            string
	RegistrationTimestamp      string
	RegistrationNonce          string
	RegistrationIdempotencyKey string
	RegistrationSignature      []byte
	RegisteredAt               string
	PayloadHash                string
	ReceiptSignature           []byte
}

type RegistrationInput struct {
	SignerFingerprint         string
	Nonce                     string
	IdempotencyKey            string
	PayloadHash               string
	RequestHash               string
	RequestTimestamp          string
	RequestSignature          []byte
	PublicKeyDER              []byte
	KeyAlgorithm              string
	SoftwareVersion           string
	CandidateDeploymentID     string
	CandidateRegisteredAt     string
	CandidateReceiptSignature []byte
}

type BatchInput struct {
	RegistryScope       string
	Signer              string
	Nonce               string
	IdempotencyKey      string
	PayloadHash         string
	RequestHash         string
	DeploymentID        string
	RequestTimestamp    string
	DeploymentSignature []byte
	CandidateBatchID    string
	Kind                string
	Period              string
	RulesetVersion      string
	QualifiedMAUCount   int64
	CommitmentHash      string
	AcceptedAt          string
	CheckpointDate      string
}

type BatchRecord struct {
	BatchID           string
	DeploymentID      string
	IdempotencyKey    string
	Kind              string
	Period            string
	RulesetVersion    string
	QualifiedMAUCount int64
	CommitmentHash    string
	PayloadHash       string
	AcceptedAt        string
	LedgerEntry       protocol.LedgerEntry
	ReceiptSignature  []byte
}

type LedgerHead struct {
	LedgerIndex int64
	EntryCount  int64
	EntryHash   string
	AcceptedAt  string
}

type CheckpointRecord struct {
	Checkpoint protocol.Checkpoint
	Signature  []byte
}

type BatchReceiptSigner func(entry protocol.LedgerEntry, checkpointDate string) ([]byte, error)
type CheckpointSigner func(checkpoint protocol.Checkpoint) ([]byte, error)

type Store interface {
	Close() error
	Ping(context.Context) error

	RegistryIdentity(context.Context) (*RegistryIdentity, error)
	EnsureRegistryIdentity(context.Context, RegistryIdentity) error

	RegisterDeployment(context.Context, RegistrationInput) (Deployment, bool, error)
	Deployment(context.Context, string) (Deployment, error)

	AcceptInstallationBatch(context.Context, BatchInput, BatchReceiptSigner) (BatchRecord, bool, error)
	BatchReceipt(context.Context, string) (BatchRecord, error)

	LedgerHead(context.Context) (LedgerHead, error)
	VerifyLedger(context.Context) error
	VerifyRecords(context.Context, ed25519.PublicKey, string, string) error
	FinalizeCompletedCheckpoints(context.Context, time.Time, string, string, CheckpointSigner) ([]CheckpointRecord, error)
	Checkpoint(context.Context, string) (CheckpointRecord, error)
	VerifyCheckpoints(context.Context, ed25519.PublicKey, string, string) error
}
