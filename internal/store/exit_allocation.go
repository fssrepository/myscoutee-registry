package store

import (
	"context"
	"crypto/ed25519"
)

type ExitAllocationCreateInput struct {
	ExitReviewID                         string
	ExitVerificationEventHash            string
	DecisionMode                         string
	OwnershipTransferID                  string
	OwnershipTransferCompletionEventHash string
	BeneficiaryID                        string
	ContractReference                    string
	ContractTermsHash                    string
	EvidenceHash                         string
	ActorID                              string
	IdempotencyKey                       string
	CandidateAllocationID                string
	CandidateEventID                     string
	AcceptedAt                           string
	RegistryScope                        string
	RegistryKeyID                        string
}

type ExitAllocationVerifyInput struct {
	AllocationID    string
	ActorID         string
	Reference       string
	EvidenceHash    string
	IdempotencyKey  string
	PayloadHash     string
	CandidateEventID string
	AcceptedAt      string
	RegistryScope   string
	RegistryKeyID   string
}

type ExitAllocationSettlementSource struct {
	BoundaryOrder            int64
	SettlementID             string
	Period                   string
	CurrencyCode             string
	FractionDigits           int64
	Revision                 int64
	LedgerIndex              int64
	SettlementHash           string
	SourceFingerprint        string
	SettlementAllocationHash string
	DistributableMinor       int64
}

type ExitAllocationCurrency struct {
	AllocationOrder    int64
	CurrencyCode       string
	FractionDigits     int64
	DistributableMinor int64
	AllocatedMinor     int64
	BeneficiaryType    string
	BeneficiaryID      string
}

type ExitAllocationRecord struct {
	AllocationID                          string
	RulesetVersion                        string
	ExitReviewID                          string
	TargetDeploymentID                    string
	ClaimActionID                         string
	SourceGroupID                         string
	ExitRecordHash                        string
	ExitVerificationEventIndex            int64
	ExitVerificationEventHash             string
	ExitEvidenceHash                      string
	DecisionMode                          string
	OwnershipTransferID                   string
	OwnershipTransferCompletionEventIndex int64
	OwnershipTransferCompletionEventHash  string
	ThroughOwnershipTransferEventIndex    int64
	OwnershipTransferHeadHash             string
	BeneficiaryType                       string
	BeneficiaryID                         string
	ContractReference                     string
	ContractTermsHash                     string
	EvidenceHash                          string
	SettlementSourceCount                 int64
	SettlementSourceHash                  string
	CurrencyAllocationCount               int64
	CurrencyAllocationHash                string
	CreatedAt                             string
	RecordHash                            string
	RegistryScope                         string
	RegistryKeyID                         string
	SettlementSources                     []ExitAllocationSettlementSource
	CurrencyAllocations                   []ExitAllocationCurrency
}

type ExitAllocationEvent struct {
	EventIndex                  int64
	EventID                     string
	AllocationID                string
	Action                      string
	ResultingStatus             string
	ActorRole                   string
	ActorID                     string
	Reference                   string
	EvidenceHash                string
	IdempotencyKey              string
	PayloadHash                 string
	RecordHash                  string
	AcceptedAt                  string
	PreviousEventHash           string
	PreviousAllocationEventHash string
	EventHash                   string
	RegistryScope               string
	RegistryKeyID               string
	Signature                   []byte
}

type ExitAllocation struct {
	Record             ExitAllocationRecord
	Status             string
	LatestEventIndex   int64
	LatestEventHash    string
	LatestAction       string
	LatestActorRole    string
	LatestActorID      string
	LatestReference    string
	LatestEvidenceHash string
	LatestAcceptedAt   string
	Events             []ExitAllocationEvent
}

type ExitAllocationQuery struct {
	Status           string
	DecisionMode     string
	Limit            int
	BeforeEventIndex int64
}

type ExitAllocationPage struct {
	Items          []ExitAllocation
	NextEventIndex int64
}

type ExitAllocationEventSigner func(ExitAllocationEvent) ([]byte, error)

type ExitAllocationStore interface {
	CreateExitAllocation(
		context.Context,
		ExitAllocationCreateInput,
		ExitAllocationEventSigner,
	) (ExitAllocationEvent, ExitAllocation, bool, error)
	VerifyExitAllocation(
		context.Context,
		ExitAllocationVerifyInput,
		ExitAllocationEventSigner,
	) (ExitAllocationEvent, ExitAllocation, bool, error)
	ExitAllocation(context.Context, string) (ExitAllocation, error)
	ExitAllocations(
		context.Context,
		ExitAllocationQuery,
	) (ExitAllocationPage, error)
	VerifyExitAllocations(
		context.Context,
		ed25519.PublicKey,
		string,
		string,
	) error
}
