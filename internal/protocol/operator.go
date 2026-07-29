package protocol

import (
	"strconv"
)

const (
	OperatorActionPath            = "/v1/operator/actions"
	OperatorClaimStatusPathPrefix = "/v1/operator/claims/"
	LeaderboardPath               = "/v1/leaderboard"

	OperatorActionClaim                = "claim"
	OperatorActionWithdrawClaim        = "withdraw-claim"
	OperatorActionIssueClientToken     = "issue-client-token"
	OperatorActionRevokeClientToken    = "revoke-client-token"
	OperatorActionRedeemClientToken    = "redeem-client-token"
	OperatorActionRevokeGroupLink      = "revoke-group-link"
	OperatorActionDeactivateDeployment = "deactivate-deployment"
	OperatorActionReactivateDeployment = "reactivate-deployment"

	OperatorAuditZeroHash       = ZeroHash
	OperatorClaimReviewZeroHash = ZeroHash

	OperatorClaimStateClaimed       = "claimed"
	OperatorClaimStatePendingReview = "pending-review"
	OperatorClaimStateApproved      = "approved"
	OperatorClaimStateRejected      = "rejected"
	OperatorClaimStateWithdrawn     = "withdrawn"

	OperatorClaimReviewApproved = "approved"
	OperatorClaimReviewRejected = "rejected"

	OperatorVerificationStatusPendingReview = "PENDING_REVIEW"
	OperatorVerificationStatusApproved      = "APPROVED"
	OperatorVerificationStatusRejected      = "REJECTED"
	OperatorVerificationStatusWithdrawn     = "WITHDRAWN"

	LeaderboardFormulaVersion = "six-complete-month-average-v1"
	LeaderboardRulesetVersion = "qmau-v1"
	FounderContributionUnits  = int64(100_000)
)

type OperatorActionRequest struct {
	ProtocolVersion          string `json:"protocol_version"`
	RegistryScope            string `json:"registry_scope"`
	DeploymentID             string `json:"deployment_id"`
	Timestamp                string `json:"timestamp"`
	Nonce                    string `json:"nonce"`
	IdempotencyKey           string `json:"idempotency_key"`
	Action                   string `json:"action"`
	OperatorName             string `json:"operator_name,omitempty"`
	OperatorAvatarURL        string `json:"operator_avatar_url,omitempty"`
	LegalName                string `json:"legal_name,omitempty"`
	RegistrationNumber       string `json:"registration_number,omitempty"`
	Jurisdiction             string `json:"jurisdiction,omitempty"`
	RegisteredAddress        string `json:"registered_address,omitempty"`
	Website                  string `json:"website,omitempty"`
	VerificationContactName  string `json:"verification_contact_name,omitempty"`
	VerificationContactRole  string `json:"verification_contact_role,omitempty"`
	VerificationContactEmail string `json:"verification_contact_email,omitempty"`
	AuthorityAttested        bool   `json:"authority_attested,omitempty"`
	ClientToken              string `json:"client_token,omitempty"`
	TokenTTLSeconds          int64  `json:"token_ttl_seconds,omitempty"`
	TokenID                  string `json:"token_id,omitempty"`
	LinkID                   string `json:"link_id,omitempty"`
	PayloadHash              string `json:"payload_hash"`
	Signature                string `json:"signature"`
}

type OperatorActionReceipt struct {
	AuditIndex              int64  `json:"audit_index"`
	AuditHash               string `json:"audit_hash"`
	PreviousAuditHash       string `json:"previous_audit_hash"`
	ActionID                string `json:"action_id"`
	DeploymentID            string `json:"deployment_id"`
	SubjectDeploymentID     string `json:"subject_deployment_id"`
	RelatedDeploymentID     string `json:"related_deployment_id,omitempty"`
	Action                  string `json:"action"`
	AcceptedAt              string `json:"accepted_at"`
	ClaimState              string `json:"claim_state,omitempty"`
	GroupID                 string `json:"group_id,omitempty"`
	LinkID                  string `json:"link_id,omitempty"`
	TokenID                 string `json:"token_id,omitempty"`
	ClientToken             string `json:"client_token,omitempty"`
	ClientTokenHash         string `json:"client_token_hash,omitempty"`
	SourceClaimActionID     string `json:"source_claim_action_id,omitempty"`
	SourcePrivateRecordHash string `json:"source_private_record_hash,omitempty"`
	TokenExpiresAt          string `json:"token_expires_at,omitempty"`
	RegistryScope           string `json:"registry_scope"`
	RegistryKeyID           string `json:"registry_key_id"`
	Signature               string `json:"signature"`
}

type OperatorActionResponse struct {
	ProtocolVersion string                `json:"protocol_version"`
	RegistryScope   string                `json:"registry_scope"`
	Duplicate       bool                  `json:"duplicate"`
	Receipt         OperatorActionReceipt `json:"receipt"`
}

type OperatorClaimStatusReceipt struct {
	DeploymentID       string `json:"deployment_id"`
	ClaimActionID      string `json:"claim_action_id"`
	ClaimAuditIndex    int64  `json:"claim_audit_index"`
	ClaimAuditHash     string `json:"claim_audit_hash"`
	GroupID            string `json:"group_id"`
	LegalName          string `json:"legal_name"`
	VerificationStatus string `json:"verification_status"`
	SubmittedAt        string `json:"submitted_at"`
	ReviewID           string `json:"review_id,omitempty"`
	ReviewIndex        int64  `json:"review_index,omitempty"`
	ReviewHash         string `json:"review_hash"`
	ApprovedAt         string `json:"approved_at,omitempty"`
	RegistryScope      string `json:"registry_scope"`
	RegistryKeyID      string `json:"registry_key_id"`
	Signature          string `json:"signature"`
}

type OperatorClaimStatusResponse struct {
	ProtocolVersion string                     `json:"protocol_version"`
	RegistryScope   string                     `json:"registry_scope"`
	Status          OperatorClaimStatusReceipt `json:"status"`
}

type OperatorClaimReviewReceipt struct {
	ReviewIndex        int64  `json:"review_index"`
	ReviewID           string `json:"review_id"`
	DeploymentID       string `json:"deployment_id"`
	ClaimActionID      string `json:"claim_action_id"`
	GroupID            string `json:"group_id"`
	LegalName          string `json:"legal_name"`
	Decision           string `json:"decision"`
	ReviewerID         string `json:"reviewer_id"`
	ReviewReference    string `json:"review_reference"`
	ReasonCode         string `json:"reason_code,omitempty"`
	IdempotencyKey     string `json:"idempotency_key"`
	ReviewedAt         string `json:"reviewed_at"`
	PreviousReviewHash string `json:"previous_review_hash"`
	ReviewHash         string `json:"review_hash"`
	RegistryScope      string `json:"registry_scope"`
	RegistryKeyID      string `json:"registry_key_id"`
	Signature          string `json:"signature"`
}

type OperatorClaimReviewResult struct {
	Duplicate bool                       `json:"duplicate"`
	Receipt   OperatorClaimReviewReceipt `json:"receipt"`
}

type OperatorClaimReviewListItem struct {
	DeploymentID       string `json:"deployment_id"`
	ClaimActionID      string `json:"claim_action_id"`
	GroupID            string `json:"group_id"`
	LegalName          string `json:"legal_name"`
	VerificationStatus string `json:"verification_status"`
	SubmittedAt        string `json:"submitted_at"`
	ApprovedAt         string `json:"approved_at,omitempty"`
	ReviewID           string `json:"review_id,omitempty"`
}

type OperatorClaimReviewDetail struct {
	OperatorClaimReviewListItem
	RegistrationNumber       string `json:"registration_number"`
	Jurisdiction             string `json:"jurisdiction"`
	RegisteredAddress        string `json:"registered_address"`
	Website                  string `json:"website,omitempty"`
	VerificationContactName  string `json:"verification_contact_name"`
	VerificationContactRole  string `json:"verification_contact_role"`
	VerificationContactEmail string `json:"verification_contact_email"`
	AuthorityAttested        bool   `json:"authority_attested"`
}

type OperatorClaimReviewListPage struct {
	Items            []OperatorClaimReviewListItem `json:"items"`
	NextDeploymentID string                        `json:"next_deployment_id,omitempty"`
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

func IsOperatorClaimReviewReasonCode(value string) bool {
	if len(value) < 3 || len(value) > 64 ||
		value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range []byte(value[1:]) {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '-' {
			continue
		}
		return false
	}
	return true
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

// OperatorClaimPayload is deliberately versioned separately from the legacy
// operator action payload. This lets upgraded registries continue to verify
// pre-verification claim audit rows while requiring every newly accepted claim
// to commit to the complete, structured verification submission.
func OperatorClaimPayload(
	legalName string,
	registrationNumber string,
	jurisdiction string,
	registeredAddress string,
	website string,
	verificationContactName string,
	verificationContactRole string,
	verificationContactEmail string,
	authorityAttested bool,
	operatorAvatarURL string,
) []byte {
	return canonical(
		"myscoutee-registry-operator-claim-payload-v2",
		OperatorActionClaim,
		legalName,
		registrationNumber,
		jurisdiction,
		registeredAddress,
		website,
		verificationContactName,
		verificationContactRole,
		verificationContactEmail,
		strconv.FormatBool(authorityAttested),
		operatorAvatarURL,
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
	sourceClaimActionID string,
	sourcePrivateRecordHash string,
	tokenExpiresAt string,
	previousAuditHash string,
) []byte {
	if sourceClaimActionID != "" || sourcePrivateRecordHash != "" {
		return canonical(
			"myscoutee-registry-operator-audit-v2",
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
			sourceClaimActionID,
			sourcePrivateRecordHash,
			tokenExpiresAt,
			previousAuditHash,
		)
	}
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
	if receipt.SourceClaimActionID != "" || receipt.SourcePrivateRecordHash != "" {
		return canonical(
			"myscoutee-registry-operator-action-receipt-v2",
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
			receipt.SourceClaimActionID,
			receipt.SourcePrivateRecordHash,
			receipt.TokenExpiresAt,
			receipt.RegistryScope,
			receipt.RegistryKeyID,
		)
	}
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

func OperatorClaimPrivateRecordMessage(
	claimActionID string,
	deploymentID string,
	groupID string,
	payloadHash string,
	legalName string,
	registrationNumber string,
	jurisdiction string,
	registeredAddress string,
	website string,
	verificationContactName string,
	verificationContactRole string,
	verificationContactEmail string,
	authorityAttested bool,
	operatorAvatarURL string,
	submittedAt string,
) []byte {
	return canonical(
		"myscoutee-registry-operator-claim-private-record-v1",
		claimActionID,
		deploymentID,
		groupID,
		payloadHash,
		legalName,
		registrationNumber,
		jurisdiction,
		registeredAddress,
		website,
		verificationContactName,
		verificationContactRole,
		verificationContactEmail,
		strconv.FormatBool(authorityAttested),
		operatorAvatarURL,
		submittedAt,
	)
}

func OperatorClaimReviewHashMessage(receipt OperatorClaimReviewReceipt) []byte {
	if receipt.ReasonCode != "" {
		return canonical(
			"myscoutee-registry-operator-claim-review-v2",
			strconv.FormatInt(receipt.ReviewIndex, 10),
			receipt.ReviewID,
			receipt.DeploymentID,
			receipt.ClaimActionID,
			receipt.GroupID,
			receipt.LegalName,
			receipt.Decision,
			receipt.ReviewerID,
			receipt.ReviewReference,
			receipt.ReasonCode,
			receipt.IdempotencyKey,
			receipt.ReviewedAt,
			receipt.PreviousReviewHash,
			receipt.RegistryScope,
			receipt.RegistryKeyID,
		)
	}
	return canonical(
		"myscoutee-registry-operator-claim-review-v1",
		strconv.FormatInt(receipt.ReviewIndex, 10),
		receipt.ReviewID,
		receipt.DeploymentID,
		receipt.ClaimActionID,
		receipt.GroupID,
		receipt.LegalName,
		receipt.Decision,
		receipt.ReviewerID,
		receipt.ReviewReference,
		receipt.IdempotencyKey,
		receipt.ReviewedAt,
		receipt.PreviousReviewHash,
		receipt.RegistryScope,
		receipt.RegistryKeyID,
	)
}

func OperatorClaimReviewReceiptMessage(receipt OperatorClaimReviewReceipt) []byte {
	return canonical(
		"myscoutee-registry-operator-claim-review-receipt-v1",
		receipt.ReviewHash,
		receipt.RegistryKeyID,
	)
}

func OperatorClaimStatusReceiptMessage(status OperatorClaimStatusReceipt) []byte {
	return canonical(
		"myscoutee-registry-operator-claim-status-receipt-v1",
		status.DeploymentID,
		status.ClaimActionID,
		strconv.FormatInt(status.ClaimAuditIndex, 10),
		status.ClaimAuditHash,
		status.GroupID,
		status.LegalName,
		status.VerificationStatus,
		status.SubmittedAt,
		status.ReviewID,
		strconv.FormatInt(status.ReviewIndex, 10),
		status.ReviewHash,
		status.ApprovedAt,
		status.RegistryScope,
		status.RegistryKeyID,
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
