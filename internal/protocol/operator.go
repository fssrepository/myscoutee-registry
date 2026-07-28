package protocol

import (
	"strconv"
)

const (
	OperatorActionPath = "/v1/operator/actions"
	LeaderboardPath    = "/v1/leaderboard"

	OperatorActionClaim                = "claim"
	OperatorActionWithdrawClaim        = "withdraw-claim"
	OperatorActionIssueClientToken     = "issue-client-token"
	OperatorActionRevokeClientToken    = "revoke-client-token"
	OperatorActionRedeemClientToken    = "redeem-client-token"
	OperatorActionRevokeGroupLink      = "revoke-group-link"
	OperatorActionDeactivateDeployment = "deactivate-deployment"
	OperatorActionReactivateDeployment = "reactivate-deployment"

	OperatorAuditZeroHash = ZeroHash

	LeaderboardFormulaVersion = "six-complete-month-average-v1"
	LeaderboardRulesetVersion = "qmau-v1"
	FounderContributionUnits  = int64(100_000)
)

type OperatorActionRequest struct {
	ProtocolVersion   string `json:"protocol_version"`
	RegistryScope     string `json:"registry_scope"`
	DeploymentID      string `json:"deployment_id"`
	Timestamp         string `json:"timestamp"`
	Nonce             string `json:"nonce"`
	IdempotencyKey    string `json:"idempotency_key"`
	Action            string `json:"action"`
	OperatorName      string `json:"operator_name,omitempty"`
	OperatorAvatarURL string `json:"operator_avatar_url,omitempty"`
	ClientToken       string `json:"client_token,omitempty"`
	TokenTTLSeconds   int64  `json:"token_ttl_seconds,omitempty"`
	TokenID           string `json:"token_id,omitempty"`
	LinkID            string `json:"link_id,omitempty"`
	PayloadHash       string `json:"payload_hash"`
	Signature         string `json:"signature"`
}

type OperatorActionReceipt struct {
	AuditIndex          int64  `json:"audit_index"`
	AuditHash           string `json:"audit_hash"`
	PreviousAuditHash   string `json:"previous_audit_hash"`
	ActionID            string `json:"action_id"`
	DeploymentID        string `json:"deployment_id"`
	SubjectDeploymentID string `json:"subject_deployment_id"`
	RelatedDeploymentID string `json:"related_deployment_id,omitempty"`
	Action              string `json:"action"`
	AcceptedAt          string `json:"accepted_at"`
	ClaimState          string `json:"claim_state,omitempty"`
	GroupID             string `json:"group_id,omitempty"`
	LinkID              string `json:"link_id,omitempty"`
	TokenID             string `json:"token_id,omitempty"`
	ClientToken         string `json:"client_token,omitempty"`
	ClientTokenHash     string `json:"client_token_hash,omitempty"`
	TokenExpiresAt      string `json:"token_expires_at,omitempty"`
	RegistryScope       string `json:"registry_scope"`
	RegistryKeyID       string `json:"registry_key_id"`
	Signature           string `json:"signature"`
}

type OperatorActionResponse struct {
	ProtocolVersion string                `json:"protocol_version"`
	RegistryScope   string                `json:"registry_scope"`
	Duplicate       bool                  `json:"duplicate"`
	Receipt         OperatorActionReceipt `json:"receipt"`
}

type LeaderboardSnapshotDto struct {
	SnapshotID                string `json:"snapshot_id"`
	FormulaVersion            string `json:"formula_version"`
	RulesetVersion            string `json:"ruleset_version"`
	ThroughPeriod             string `json:"through_period"`
	ThroughLedgerIndex        int64  `json:"through_ledger_index"`
	ThroughAuditIndex         int64  `json:"through_audit_index"`
	LedgerHeadHash            string `json:"ledger_head_hash"`
	AuditHeadHash             string `json:"audit_head_hash"`
	FounderUnitsNumerator     string `json:"founder_units_numerator"`
	FounderUnitsDenominator   string `json:"founder_units_denominator"`
	FounderShareNumerator     string `json:"founder_share_numerator"`
	FounderShareDenominator   string `json:"founder_share_denominator"`
	MeasuredWeightNumerator   string `json:"measured_weight_numerator"`
	MeasuredWeightDenominator string `json:"measured_weight_denominator"`
	ClaimedWeightNumerator    string `json:"claimed_weight_numerator"`
	ClaimedWeightDenominator  string `json:"claimed_weight_denominator"`
	CreatedAt                 string `json:"created_at"`
	SnapshotHash              string `json:"snapshot_hash"`
	RegistryScope             string `json:"registry_scope"`
	RegistryKeyID             string `json:"registry_key_id"`
	Signature                 string `json:"signature"`
}

type LeaderboardRowDto struct {
	RowID             string `json:"row_id"`
	View              string `json:"view"`
	GroupID           string `json:"group_id,omitempty"`
	Label             string `json:"label"`
	AvatarURL         string `json:"avatar_url,omitempty"`
	ClaimState        string `json:"claim_state"`
	DeploymentCount   int64  `json:"deployment_count"`
	WeightNumerator   string `json:"weight_numerator"`
	WeightDenominator string `json:"weight_denominator"`
	ShareNumerator    string `json:"share_numerator"`
	ShareDenominator  string `json:"share_denominator"`
}

type LeaderboardPageDto struct {
	Snapshot   LeaderboardSnapshotDto `json:"snapshot"`
	View       string                 `json:"view"`
	Items      []LeaderboardRowDto    `json:"items"`
	NextCursor string                 `json:"next_cursor,omitempty"`
}

type LeaderboardDeploymentDto struct {
	DeploymentID      string `json:"deployment_id"`
	GroupID           string `json:"group_id,omitempty"`
	ClaimState        string `json:"claim_state"`
	MembershipState   string `json:"membership_state"`
	WeightNumerator   string `json:"weight_numerator"`
	WeightDenominator string `json:"weight_denominator"`
	ShareNumerator    string `json:"share_numerator"`
	ShareDenominator  string `json:"share_denominator"`
}

type LeaderboardDeploymentPageDto struct {
	Snapshot   LeaderboardSnapshotDto     `json:"snapshot"`
	GroupID    string                     `json:"group_id"`
	Items      []LeaderboardDeploymentDto `json:"items"`
	NextCursor string                     `json:"next_cursor,omitempty"`
}

func OperatorActionPayload(
	action string,
	operatorName string,
	operatorAvatarURL string,
	clientTokenHash string,
	tokenTTLSeconds int64,
	tokenID string,
	linkID string,
) []byte {
	return canonical(
		"myscoutee-registry-operator-action-payload-v1",
		action,
		operatorName,
		operatorAvatarURL,
		clientTokenHash,
		strconv.FormatInt(tokenTTLSeconds, 10),
		tokenID,
		linkID,
	)
}

func OperatorAuditMessage(
	auditIndex int64,
	actionID string,
	deploymentID string,
	subjectDeploymentID string,
	relatedDeploymentID string,
	action string,
	payloadHash string,
	acceptedAt string,
	claimState string,
	groupID string,
	linkID string,
	tokenID string,
	clientTokenHash string,
	tokenExpiresAt string,
	previousAuditHash string,
) []byte {
	return canonical(
		"myscoutee-registry-operator-audit-v1",
		strconv.FormatInt(auditIndex, 10),
		actionID,
		deploymentID,
		subjectDeploymentID,
		relatedDeploymentID,
		action,
		payloadHash,
		acceptedAt,
		claimState,
		groupID,
		linkID,
		tokenID,
		clientTokenHash,
		tokenExpiresAt,
		previousAuditHash,
	)
}

func OperatorActionReceiptMessage(receipt OperatorActionReceipt) []byte {
	return canonical(
		"myscoutee-registry-operator-action-receipt-v1",
		strconv.FormatInt(receipt.AuditIndex, 10),
		receipt.AuditHash,
		receipt.PreviousAuditHash,
		receipt.ActionID,
		receipt.DeploymentID,
		receipt.SubjectDeploymentID,
		receipt.RelatedDeploymentID,
		receipt.Action,
		receipt.AcceptedAt,
		receipt.ClaimState,
		receipt.GroupID,
		receipt.LinkID,
		receipt.TokenID,
		receipt.ClientTokenHash,
		receipt.TokenExpiresAt,
		receipt.RegistryScope,
		receipt.RegistryKeyID,
	)
}

func LeaderboardSnapshotMessage(snapshot LeaderboardSnapshotDto) []byte {
	return canonical(
		"myscoutee-registry-leaderboard-snapshot-receipt-v1",
		snapshot.SnapshotHash,
		snapshot.RegistryKeyID,
	)
}

func LeaderboardSnapshotHashMessage(snapshot LeaderboardSnapshotDto) []byte {
	return canonical(
		"myscoutee-registry-leaderboard-snapshot-hash-v1",
		snapshot.SnapshotID,
		snapshot.FormulaVersion,
		snapshot.RulesetVersion,
		snapshot.ThroughPeriod,
		strconv.FormatInt(snapshot.ThroughLedgerIndex, 10),
		strconv.FormatInt(snapshot.ThroughAuditIndex, 10),
		snapshot.LedgerHeadHash,
		snapshot.AuditHeadHash,
		snapshot.FounderUnitsNumerator,
		snapshot.FounderUnitsDenominator,
		snapshot.FounderShareNumerator,
		snapshot.FounderShareDenominator,
		snapshot.MeasuredWeightNumerator,
		snapshot.MeasuredWeightDenominator,
		snapshot.ClaimedWeightNumerator,
		snapshot.ClaimedWeightDenominator,
		snapshot.CreatedAt,
		snapshot.RegistryScope,
		snapshot.RegistryKeyID,
	)
}
