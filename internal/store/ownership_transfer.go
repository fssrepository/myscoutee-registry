package store

import (
	"context"
	"crypto/ed25519"
)

type OwnershipTransferPrepareInput struct {
	ExitReviewID              string
	TargetDeploymentID        string
	ClaimActionID             string
	SourceGroupID             string
	TargetGroupID             string
	ExitVerificationEventHash string
	ActorID                   string
	Reference                 string
	EvidenceHash              string
	IdempotencyKey            string
	CandidateTransferID       string
	CandidateEventID          string
	AcceptedAt                string
	RegistryScope             string
	RegistryKeyID             string
}

type OwnershipTransferMutationInput struct {
	TransferID       string
	Action           string
	ResultingStatus  string
	EffectiveDate    string
	ActorID          string
	Reference        string
	EvidenceHash     string
	ReasonCode       string
	IdempotencyKey   string
	PayloadHash      string
	CandidateEventID string
	AcceptedAt       string
	RegistryScope    string
	RegistryKeyID    string
}

type OwnershipTransferRecord struct {
	TransferID                 string
	RulesetVersion             string
	ExitReviewID               string
	TargetDeploymentID         string
	ClaimActionID              string
	SourceGroupID              string
	TargetGroupID              string
	LegalName                  string
	ExitRecordHash             string
	ExitVerificationEventIndex int64
	ExitVerificationEventHash  string
	ExitEvidenceHash           string
	PreparedAt                 string
	RecordHash                 string
	RegistryScope              string
	RegistryKeyID              string
}

type OwnershipTransferEvent struct {
	EventIndex                int64
	EventID                   string
	TransferID                string
	Action                    string
	ResultingStatus           string
	EffectiveDate             string
	ActorRole                 string
	ActorID                   string
	Reference                 string
	EvidenceHash              string
	ReasonCode                string
	IdempotencyKey            string
	PayloadHash               string
	RecordHash                string
	AcceptedAt                string
	PreviousEventHash         string
	PreviousTransferEventHash string
	EventHash                 string
	RegistryScope             string
	RegistryKeyID             string
	Signature                 []byte
}

type OwnershipTransferMembership struct {
	TransferID           string
	CompletionEventIndex int64
	CompletionEventHash  string
	TargetDeploymentID   string
	ClaimActionID        string
	SourceGroupID        string
	TargetGroupID        string
	EffectiveDate        string
	ThroughAuditIndex    int64
	AuditHeadHash        string
	CompletedAt          string
	MembershipHash       string
}

type OwnershipTransfer struct {
	Record              OwnershipTransferRecord
	Status              string
	LatestEventIndex    int64
	LatestEventHash     string
	LatestAction        string
	LatestEffectiveDate string
	LatestActorRole     string
	LatestActorID       string
	LatestReference     string
	LatestEvidenceHash  string
	LatestReasonCode    string
	LatestAcceptedAt    string
	Membership          *OwnershipTransferMembership
	Events              []OwnershipTransferEvent
}

type OwnershipTransferQuery struct {
	Status           string
	Limit            int
	BeforeEventIndex int64
}

type OwnershipTransferPage struct {
	Items          []OwnershipTransfer
	NextEventIndex int64
}

type OwnershipTransferEventSigner func(OwnershipTransferEvent) ([]byte, error)

type OwnershipTransferStore interface {
	PrepareOwnershipTransfer(
		context.Context,
		OwnershipTransferPrepareInput,
		OwnershipTransferEventSigner,
	) (OwnershipTransferEvent, OwnershipTransfer, bool, error)
	AppendOwnershipTransferEvent(
		context.Context,
		OwnershipTransferMutationInput,
		OwnershipTransferEventSigner,
	) (OwnershipTransferEvent, OwnershipTransfer, bool, error)
	OwnershipTransfer(context.Context, string) (OwnershipTransfer, error)
	OwnershipTransfers(
		context.Context,
		OwnershipTransferQuery,
	) (OwnershipTransferPage, error)
	OwnershipTransferHead(context.Context) (OwnershipTransferEvent, error)
	VerifyOwnershipTransfers(
		context.Context,
		ed25519.PublicKey,
		string,
		string,
	) error
}
