package store

import (
	"context"
	"crypto/ed25519"
)

type ExitReviewFreezeInput struct {
	RecordDate           string
	TargetDeploymentID   string
	ClaimActionID        string
	GroupID              string
	ActorRole            string
	ActorID              string
	Reference            string
	EvidenceHash         string
	IdempotencyKey       string
	CandidateReviewID    string
	CandidateEventID     string
	AcceptedAt           string
	RegistryScope        string
	RegistryKeyID        string
}

type ExitReviewMutationInput struct {
	ReviewID         string
	Action           string
	ResultingStatus  string
	EffectiveDate    string
	ActorRole        string
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

type ExitReviewDeployment struct {
	MemberOrder       int64
	DeploymentID     string
	ClaimActionID    string
	ClaimState       string
	EligibilityState string
	ClaimAuditIndex  int64
	ClaimAuditHash   string
	ReviewIndex      int64
	ReviewHash       string
	EligibilityIndex int64
	EligibilityHash  string
}

type ExitReviewSettlementBoundary struct {
	BoundaryOrder      int64
	SettlementID       string
	Period             string
	CurrencyCode       string
	Revision           int64
	LedgerIndex        int64
	SettlementHash     string
	SourceFingerprint  string
	AllocationHash     string
}

type ExitReviewRecord struct {
	ReviewID                     string
	RulesetVersion               string
	RecordDate                   string
	TargetDeploymentID           string
	ClaimActionID                string
	GroupID                      string
	LegalName                    string
	CheckpointHash               string
	ThroughLedgerIndex           int64
	LedgerHeadHash               string
	MerkleTreeSize               int64
	MerkleRootHash               string
	ThroughAuditIndex            int64
	AuditHeadHash                string
	ThroughReviewIndex           int64
	ClaimReviewHeadHash          string
	ThroughEligibilityIndex      int64
	EligibilityHeadHash          string
	ThroughSettlementLedgerIndex int64
	SettlementBoundaryCount      int64
	SettlementBoundaryHash       string
	DeploymentCount              int64
	MembershipHash               string
	FrozenAt                     string
	RecordHash                   string
	RegistryScope                string
	RegistryKeyID                string
	Deployments                  []ExitReviewDeployment
	Settlements                  []ExitReviewSettlementBoundary
}

type ExitReviewEvent struct {
	EventIndex             int64
	EventID                string
	ReviewID               string
	Action                 string
	ResultingStatus        string
	EffectiveDate          string
	ActorRole              string
	ActorID                string
	Reference              string
	EvidenceHash           string
	ReasonCode             string
	IdempotencyKey         string
	PayloadHash            string
	RecordHash             string
	AcceptedAt             string
	PreviousEventHash      string
	PreviousReviewEventHash string
	EventHash              string
	RegistryScope          string
	RegistryKeyID          string
	Signature              []byte
}

type ExitReview struct {
	Record              ExitReviewRecord
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
	Events              []ExitReviewEvent
}

type ExitReviewQuery struct {
	Status           string
	Limit            int
	BeforeEventIndex int64
}

type ExitReviewPage struct {
	Items          []ExitReview
	NextEventIndex int64
}

type ExitReviewEventSigner func(ExitReviewEvent) ([]byte, error)

type ExitReviewStore interface {
	FreezeExitReview(
		context.Context,
		ExitReviewFreezeInput,
		ExitReviewEventSigner,
	) (ExitReviewEvent, ExitReview, bool, error)
	AppendExitReviewEvent(
		context.Context,
		ExitReviewMutationInput,
		ExitReviewEventSigner,
	) (ExitReviewEvent, ExitReview, bool, error)
	ExitReview(context.Context, string) (ExitReview, error)
	ExitReviews(context.Context, ExitReviewQuery) (ExitReviewPage, error)
	VerifyExitReviews(context.Context, ed25519.PublicKey, string, string) error
}
