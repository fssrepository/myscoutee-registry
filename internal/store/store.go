package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

var (
	ErrNotFound                     = errors.New("record not found")
	ErrIdempotencyConflict          = errors.New("idempotency key was already used with a different payload")
	ErrReplayConflict               = errors.New("nonce was already used by a different request")
	ErrInconsistentState            = errors.New("registry database contains inconsistent state")
	ErrRegistryKeyMismatch          = errors.New("configured registry signing key does not match persisted registry identity")
	ErrAcceptedAtFinalized          = errors.New("accepted_at would alter an already finalized checkpoint")
	ErrAcceptedAtBeforeHead         = errors.New("accepted_at is before the current ledger head")
	ErrAcceptedAtBeforeIdentity     = errors.New("accepted_at is before registry identity creation")
	ErrOperatorActionConflict       = errors.New("operator action conflicts with current state")
	ErrOperatorClaimRequired        = errors.New("an active operator claim is required")
	ErrOperatorClaimStale           = errors.New("operator claim approval target is not the current pending claim")
	ErrOperatorClaimAlreadyReviewed = errors.New("operator claim is not pending review")
	ErrClientTokenExpired           = errors.New("operator client token is expired")
	ErrClientTokenRevoked           = errors.New("operator client token is revoked")
	ErrDeploymentInactive           = errors.New("deployment is inactive")
	ErrAnnouncementConflict         = errors.New("announcement publication ID was already used with different contents")
	ErrAnnouncementClockBeforeHead  = errors.New("accepted_at is before the current announcement head")
	ErrRevenueRevisionConflict      = errors.New("revenue revision does not extend the current active batch")
	ErrRevenueAggregateOverflow     = errors.New("revenue aggregate exceeds the supported signed integer range")
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

type RevenueBatchInput struct {
	RegistryScope             string
	Signer                    string
	Nonce                     string
	IdempotencyKey            string
	PayloadHash               string
	RequestHash               string
	DeploymentID              string
	RequestTimestamp          string
	DeploymentSignature       []byte
	CandidateBatchID          string
	Kind                      string
	Period                    string
	Revision                  int64
	SupersedesBatchID         string
	RulesetVersion            string
	CommissionRateBasisPoints int64
	Currencies                []protocol.RevenueCurrency
	AcceptedAt                string
	CheckpointDate            string
}

type RevenueBatchRecord struct {
	BatchID                   string
	DeploymentID              string
	IdempotencyKey            string
	Kind                      string
	Period                    string
	Revision                  int64
	SupersedesBatchID         string
	RulesetVersion            string
	CommissionRateBasisPoints int64
	CurrencyCount             int64
	Currencies                []protocol.RevenueCurrency
	PayloadHash               string
	AcceptedAt                string
	LedgerEntry               protocol.LedgerEntry
	ReceiptSignature          []byte
}

type RevenueReceiptSigner func(
	entry protocol.LedgerEntry,
	input RevenueBatchInput,
	currencyCount int64,
	checkpointDate string,
) ([]byte, error)

type RevenueQuery struct {
	Period         string
	CurrencyCode   string
	FractionDigits int64
	DeploymentID   string
	GroupID        string
}

type Store interface {
	Close() error
	Ping(context.Context) error

	RegistryIdentity(context.Context) (*RegistryIdentity, error)
	EnsureRegistryIdentity(context.Context, RegistryIdentity) error

	RegisterDeployment(context.Context, RegistrationInput) (Deployment, bool, error)
	Deployment(context.Context, string) (Deployment, error)

	AcceptInstallationBatch(context.Context, BatchInput, BatchReceiptSigner) (BatchRecord, bool, error)
	BatchReceipt(context.Context, string) (BatchRecord, error)
	AcceptRevenueBatch(context.Context, RevenueBatchInput, RevenueReceiptSigner) (RevenueBatchRecord, bool, error)
	RevenueBatchReceipt(context.Context, string) (RevenueBatchRecord, error)
	RevenueSummary(context.Context, RevenueQuery) (protocol.RevenueSummary, error)

	LedgerHead(context.Context) (LedgerHead, error)
	VerifyLedger(context.Context) error
	VerifyLedgerWeightRows(context.Context) error
	VerifyRecords(context.Context, ed25519.PublicKey, string, string) error
	FinalizeCompletedCheckpoints(context.Context, time.Time, string, string, CheckpointSigner) ([]CheckpointRecord, error)
	Checkpoint(context.Context, string) (CheckpointRecord, error)
	VerifyCheckpoints(context.Context, ed25519.PublicKey, string, string) error

	OperatorNetworkStore
	AnnouncementStore
}
