package store

import (
	"context"
	"crypto/ed25519"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

type GlobalIdentityVOPRFKey struct {
	KeyVersion  int64
	Suite       string
	PublicKey   []byte
	ActivatedAt string
}

type GlobalIdentityEvaluationInput struct {
	EvaluationID     string
	DeploymentID     string
	IdempotencyKey   string
	Nonce            string
	RequestTimestamp string
	RequestHash      string
	RequestSignature []byte
	PayloadHash      string
	KeyVersion       int64
	Suite            string
	BlindedElement   []byte
	PublicKey        []byte
	EvaluatedElement []byte
	Proof            []byte
	ResponseHash     string
	EvaluatedAt      string
	ReceiptSignature []byte
	RateWindowStart  string
	RateLimit        int64
}

type GlobalIdentityEvaluationRecord struct {
	GlobalIdentityEvaluationInput
}

type GlobalIdentityMutationInput struct {
	Action                    string
	DeploymentID              string
	IdempotencyKey            string
	Nonce                     string
	RequestTimestamp          string
	RequestHash               string
	RequestSignature          []byte
	PayloadHash               string
	CandidateEventID          string
	CandidateLinkID           string
	CandidateGlobalIdentityID string
	LinkID                    string
	KeyVersion                int64
	RequiredActiveKeyVersion  int64
	Suite                     string
	NetworkIdentityCommitment string
	ConsentVersion            string
	ConsentEvidenceCommitment string
	VerifiedAt                string
	EffectivePeriod           string
	ReasonCommitment          string
	PrivateEventHash          string
	AcceptedAt                string
	RegistryScope             string
	RegistryKeyID             string
}

type GlobalIdentityEvent struct {
	EventIndex          int64
	EventID             string
	Action              string
	DeploymentID        string
	Period              string
	AggregateCommitment string
	ReportedCount       int64
	DeduplicatedCount   int64
	AcceptedAt          string
	PreviousEventHash   string
	EventHash           string
	RegistryScope       string
	RegistryKeyID       string
	ReceiptSignature    []byte
	IdempotencyKey      string
	RequestNonce        string
	RequestTimestamp    string
	RequestHash         string
	PayloadHash         string
	RequestSignature    []byte
	PrivateEventHash    string
	SubjectID           string
}

type GlobalIdentityLink struct {
	LinkID                    string
	DeploymentID              string
	GlobalIdentityID          string
	Status                    string
	KeyVersion                int64
	Suite                     string
	NetworkIdentityCommitment string
	ConsentVersion            string
	ConsentEvidenceCommitment string
	VerifiedAt                string
	ActiveFromPeriod          string
	InactiveFromPeriod        string
	LatestEventIndex          int64
	LatestEventHash           string
}

type GlobalIdentityPresenceInput struct {
	DeploymentID             string
	IdempotencyKey           string
	Nonce                    string
	RequestTimestamp         string
	RequestHash              string
	RequestSignature         []byte
	PayloadHash              string
	CandidateEventID         string
	CandidateBatchID         string
	SubmissionID             string
	Period                   string
	Revision                 int64
	SupersedesBatchID        string
	ReportedQMAUCount        int64
	KeyVersion               int64
	RequiredActiveKeyVersion int64
	Suite                    string
	ChunkIndex               int64
	ChunkCount               int64
	TotalCommitmentCount     int64
	CommitmentSetHash        string
	Commitments              []string
	PrivateEventHash         string
	AcceptedAt               string
	RegistryScope            string
	RegistryKeyID            string
}

type GlobalIdentityPresenceRecord struct {
	BatchID                string
	SubmissionID           string
	DeploymentID           string
	RegistryScope          string
	Period                 string
	Revision               int64
	ChunkIndex             int64
	ChunkCount             int64
	ReceivedChunkCount     int64
	TotalCommitmentCount   int64
	CommitmentSetHash      string
	Complete               bool
	SupersedesBatchID      string
	ReportedQMAUCount      int64
	LinkedObservationCount int64
	UnlinkedQMAUCount      int64
	RequestHash            string
	PayloadHash            string
	AcceptedAt             string
	RegistryKeyID          string
	ReceiptHash            string
	ReceiptSignature       []byte
	Event                  GlobalIdentityEvent
	Snapshot               protocol.GlobalIdentityDedupSnapshot
}

type GlobalIdentityEventSigner func(GlobalIdentityEvent) ([]byte, error)
type GlobalIdentityPresenceReceiptSigner func(
	protocol.GlobalIdentityPresenceBatchResponse,
) ([]byte, error)

type GlobalIdentityStore interface {
	EnsureGlobalIdentityVOPRFKeys(
		context.Context,
		[]GlobalIdentityVOPRFKey,
	) error
	GlobalIdentityVOPRFKey(
		context.Context,
		int64,
	) (GlobalIdentityVOPRFKey, error)
	GlobalIdentityEvaluationByIdempotency(
		context.Context,
		string,
		string,
	) (GlobalIdentityEvaluationRecord, error)
	CountGlobalIdentityEvaluationsSince(
		context.Context,
		string,
		string,
	) (int64, error)
	AcceptGlobalIdentityEvaluation(
		context.Context,
		GlobalIdentityEvaluationInput,
	) (GlobalIdentityEvaluationRecord, bool, error)
	ApplyGlobalIdentityMutation(
		context.Context,
		GlobalIdentityMutationInput,
		GlobalIdentityEventSigner,
	) (GlobalIdentityLink, GlobalIdentityEvent, bool, error)
	AcceptGlobalIdentityPresenceBatch(
		context.Context,
		GlobalIdentityPresenceInput,
		GlobalIdentityEventSigner,
		GlobalIdentityPresenceReceiptSigner,
	) (GlobalIdentityPresenceRecord, bool, error)
	GlobalIdentityDedupSnapshot(
		context.Context,
		string,
	) (protocol.GlobalIdentityDedupSnapshot, error)
	VerifyGlobalIdentities(
		context.Context,
		ed25519.PublicKey,
		string,
		string,
	) error
}
