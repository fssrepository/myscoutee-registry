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
	AuditIndex          int64
	ActionID            string
	DeploymentID        string
	SubjectDeploymentID string
	RelatedDeploymentID string
	Action              string
	RequestTimestamp    string
	Nonce               string
	IdempotencyKey      string
	PayloadHash         string
	RequestHash         string
	DeploymentSignature []byte
	OperatorName        string
	OperatorAvatarURL   string
	ClaimState          string
	GroupID             string
	LinkID              string
	TokenID             string
	ClientTokenHash     string
	TokenTTLSeconds     int64
	TokenExpiresAt      string
	AcceptedAt          string
	PreviousAuditHash   string
	AuditHash           string
	RegistryKeyID       string
	ReceiptSignature    []byte
}

type OperatorAuditSigner func(OperatorAuditEvent) ([]byte, error)

type LeaderboardBoundary struct {
	LedgerIndex int64
	AuditIndex  int64
	LedgerHash  string
	AuditHash   string
	CreatedAt   string
}

type LeaderboardRecord struct {
	RowID           string
	View            string
	GroupID         string
	Label           string
	AvatarURL       string
	ClaimState      string
	DeploymentCount int64
	Weight          int64
}

type LeaderboardDeploymentRecord struct {
	DeploymentID    string
	GroupID         string
	ClaimState      string
	MembershipState string
	Weight          int64
}

type LeaderboardQuery struct {
	View               string
	FromPeriod         string
	ThroughPeriod      string
	ThroughLedgerIndex int64
	ThroughAuditIndex  int64
	Limit              int
	AfterWeight        int64
	AfterID            string
	HasAfter           bool
}

type LeaderboardDeploymentQuery struct {
	GroupID            string
	FromPeriod         string
	ThroughPeriod      string
	ThroughLedgerIndex int64
	ThroughAuditIndex  int64
	Limit              int
	AfterWeight        int64
	AfterID            string
	HasAfter           bool
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
	LeaderboardBoundary(context.Context) (LeaderboardBoundary, error)
	LeaderboardTotals(
		context.Context,
		string,
		string,
		int64,
		int64,
	) (LeaderboardTotals, error)
	LeaderboardRows(context.Context, LeaderboardQuery) ([]LeaderboardRecord, error)
	LeaderboardDeployments(
		context.Context,
		LeaderboardDeploymentQuery,
	) ([]LeaderboardDeploymentRecord, error)
	VerifyOperatorNetwork(context.Context, []byte, string, string) error
}
