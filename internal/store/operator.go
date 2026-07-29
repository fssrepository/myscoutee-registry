package store

import (
	"context"
)

type OperatorActionInput struct {
	RegistryScope            string
	DeploymentID             string
	Action                   string
	RequestTimestamp         string
	Nonce                    string
	IdempotencyKey           string
	PayloadHash              string
	RequestHash              string
	DeploymentSignature      []byte
	OperatorName             string
	OperatorAvatarURL        string
	LegalName                string
	RegistrationNumber       string
	Jurisdiction             string
	RegisteredAddress        string
	Website                  string
	VerificationContactName  string
	VerificationContactRole  string
	VerificationContactEmail string
	AuthorityAttested        bool
	ClientTokenHash          string
	TokenTTLSeconds          int64
	TokenID                  string
	LinkID                   string
	CandidateActionID        string
	CandidateGroupID         string
	CandidateLinkID          string
	CandidateTokenID         string
	CandidateClientTokenHash string
	CandidateTokenExpiresAt  string
	AcceptedAt               string
	RegistryKeyID            string
}

type OperatorAuditEvent struct {
	AuditIndex              int64
	ActionID                string
	DeploymentID            string
	SubjectDeploymentID     string
	RelatedDeploymentID     string
	Action                  string
	RequestTimestamp        string
	Nonce                   string
	IdempotencyKey          string
	PayloadHash             string
	RequestHash             string
	DeploymentSignature     []byte
	OperatorName            string
	OperatorAvatarURL       string
	ClaimState              string
	GroupID                 string
	LinkID                  string
	TokenID                 string
	ClientTokenHash         string
	SourceClaimActionID     string
	SourcePrivateRecordHash string
	TokenTTLSeconds         int64
	TokenExpiresAt          string
	AcceptedAt              string
	PreviousAuditHash       string
	AuditHash               string
	RegistryKeyID           string
	ReceiptSignature        []byte
}

type OperatorAuditSigner func(OperatorAuditEvent) ([]byte, error)

type OperatorClaimSubmission struct {
	ClaimActionID            string
	DeploymentID             string
	GroupID                  string
	LegalName                string
	RegistrationNumber       string
	Jurisdiction             string
	RegisteredAddress        string
	Website                  string
	VerificationContactName  string
	VerificationContactRole  string
	VerificationContactEmail string
	AuthorityAttested        bool
	OperatorAvatarURL        string
	PayloadHash              string
	SubmittedAt              string
	PrivateRecordHash        string
}

type OperatorClaimStatus struct {
	DeploymentID      string
	ClaimActionID     string
	ClaimAuditIndex   int64
	ClaimAuditHash    string
	GroupID           string
	LegalName         string
	VerificationState string
	SubmittedAt       string
	ReviewID          string
	ReviewIndex       int64
	ReviewHash        string
	ApprovedAt        string
	UpdatedAt         string
	PrivateRecordHash string
	EligibilityState  string
	EligibilityID     string
	EligibilityIndex  int64
	EligibilityHash   string
}

type OperatorClaimEligibilityInput struct {
	RegistryScope          string
	DeploymentID           string
	ClaimActionID          string
	GroupID                string
	LegalName              string
	Decision               string
	ActorID                string
	DecisionReference      string
	ReasonCode             string
	IdempotencyKey         string
	CandidateEligibilityID string
	DecidedAt              string
	RegistryKeyID          string
}

type OperatorClaimEligibility struct {
	EligibilityIndex        int64
	EligibilityID           string
	DeploymentID            string
	ClaimActionID           string
	GroupID                 string
	LegalName               string
	Decision                string
	ActorID                 string
	DecisionReference       string
	ReasonCode              string
	IdempotencyKey          string
	DecidedAt               string
	PreviousEligibilityHash string
	EligibilityHash         string
	RegistryKeyID           string
	Signature               []byte
}

type OperatorClaimEligibilitySigner func(OperatorClaimEligibility) ([]byte, error)

type OperatorClaimReviewInput struct {
	RegistryScope     string
	DeploymentID      string
	ClaimActionID     string
	GroupID           string
	LegalName         string
	Decision          string
	ReviewerID        string
	ReviewReference   string
	ReasonCode        string
	IdempotencyKey    string
	CandidateReviewID string
	ReviewedAt        string
	RegistryKeyID     string
}

type OperatorClaimReview struct {
	ReviewIndex        int64
	ReviewID           string
	DeploymentID       string
	ClaimActionID      string
	GroupID            string
	LegalName          string
	Decision           string
	ReviewerID         string
	ReviewReference    string
	ReasonCode         string
	IdempotencyKey     string
	ReviewedAt         string
	PreviousReviewHash string
	ReviewHash         string
	RegistryKeyID      string
	Signature          []byte
}

type OperatorClaimReviewSigner func(OperatorClaimReview) ([]byte, error)

type OperatorClaimQuery struct {
	Status            string
	Limit             int
	AfterDeploymentID string
}

type OperatorClaimPage struct {
	Items            []OperatorClaimStatus
	NextDeploymentID string
}

type LeaderboardBoundary struct {
	LedgerIndex        int64
	AuditIndex         int64
	ReviewIndex        int64
	EligibilityIndex   int64
	TransferEventIndex int64
	LedgerHash         string
	AuditHash          string
	ReviewHash         string
	EligibilityHash    string
	TransferEventHash  string
	CreatedAt          string
}

type LeaderboardRecord struct {
	RowID            string
	View             string
	GroupID          string
	Label            string
	AvatarURL        string
	ClaimState       string
	EligibilityState string
	DeploymentCount  int64
	Weight           int64
	SortWeight       int64
}

type LeaderboardDeploymentRecord struct {
	DeploymentID     string
	GroupID          string
	ClaimState       string
	EligibilityState string
	MembershipState  string
	Weight           int64
	SortWeight       int64
}

type LeaderboardQuery struct {
	View                      string
	FromPeriod                string
	ThroughPeriod             string
	ThroughLedgerIndex        int64
	ThroughAuditIndex         int64
	ThroughReviewIndex        int64
	ThroughEligibilityIndex   int64
	ThroughTransferEventIndex int64
	TransferEffectiveDate     string
	Limit                     int
	AfterWeight               int64
	AfterID                   string
	HasAfter                  bool
}

type LeaderboardDeploymentQuery struct {
	GroupID                   string
	FromPeriod                string
	ThroughPeriod             string
	ThroughLedgerIndex        int64
	ThroughAuditIndex         int64
	ThroughReviewIndex        int64
	ThroughEligibilityIndex   int64
	ThroughTransferEventIndex int64
	TransferEffectiveDate     string
	Limit                     int
	AfterWeight               int64
	AfterID                   string
	HasAfter                  bool
}

type LeaderboardTotals struct {
	MeasuredWeight int64
	ClaimedWeight  int64
}

type OperatorNetworkStore interface {
	AppendOperatorAction(
		context.Context,
		OperatorActionInput,
		OperatorAuditSigner,
	) (OperatorAuditEvent, bool, error)
	OperatorAuditHead(context.Context) (OperatorAuditEvent, error)
	OperatorClaimStatus(context.Context, string) (OperatorClaimStatus, error)
	OperatorClaimSubmission(context.Context, string) (OperatorClaimSubmission, OperatorClaimStatus, error)
	OperatorClaims(context.Context, OperatorClaimQuery) (OperatorClaimPage, error)
	DecideOperatorClaim(
		context.Context,
		OperatorClaimReviewInput,
		OperatorClaimReviewSigner,
	) (OperatorClaimReview, bool, error)
	DecideOperatorClaimEligibility(
		context.Context,
		OperatorClaimEligibilityInput,
		OperatorClaimEligibilitySigner,
	) (OperatorClaimEligibility, bool, error)
	OperatorClaimEligibilityHead(context.Context) (OperatorClaimEligibility, error)
	LeaderboardBoundary(context.Context) (LeaderboardBoundary, error)
	LeaderboardTotals(
		context.Context,
		string,
		string,
		int64,
		int64,
		int64,
	) (LeaderboardTotals, error)
	LeaderboardTotalsAtEligibility(
		context.Context,
		string,
		string,
		int64,
		int64,
		int64,
		int64,
	) (LeaderboardTotals, error)
	LeaderboardTotalsAtOwnershipTransfer(
		context.Context,
		string,
		string,
		int64,
		int64,
		int64,
		int64,
		int64,
		string,
	) (LeaderboardTotals, error)
	LeaderboardRows(context.Context, LeaderboardQuery) ([]LeaderboardRecord, error)
	LeaderboardDeployments(
		context.Context,
		LeaderboardDeploymentQuery,
	) ([]LeaderboardDeploymentRecord, error)
	VerifyOperatorNetwork(context.Context, []byte, string, string) error
}
