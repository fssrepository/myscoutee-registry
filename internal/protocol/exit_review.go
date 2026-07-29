package protocol

import "strconv"

const (
	ExitReviewRulesetVersion = "exit-review-v1"

	ExitReviewStatusPending  = "review-pending"
	ExitReviewStatusEligible = "verified-eligible"
	ExitReviewStatusRejected = "rejected"
	ExitReviewStatusDisputed = "disputed"
	ExitReviewStatusWithdrawn = "withdrawn"

	ExitReviewActionFreeze   = "freeze"
	ExitReviewActionVerify   = "verify"
	ExitReviewActionReject   = "reject"
	ExitReviewActionDispute  = "dispute"
	ExitReviewActionWithdraw = "withdraw"

	ExitReviewActorBuyer   = "buyer"
	ExitReviewActorAuditor = "auditor"

	ExitReviewZeroHash = ZeroHash
)

// ExitReviewDeployment pins one exact deployment/claim generation into an
// exit record. It intentionally contains no private claim-verification fields.
type ExitReviewDeployment struct {
	MemberOrder     int64  `json:"member_order"`
	DeploymentID   string `json:"deployment_id"`
	ClaimActionID  string `json:"claim_action_id"`
	ClaimAuditIndex int64  `json:"claim_audit_index"`
	ClaimAuditHash string `json:"claim_audit_hash"`
	ReviewIndex    int64  `json:"review_index"`
	ReviewHash     string `json:"review_hash"`
	EligibilityIndex int64 `json:"eligibility_index"`
	EligibilityHash string `json:"eligibility_hash"`
}

// ExitReviewSettlementBoundary commits to the newest settlement revision for
// one period/currency at the frozen ledger boundary.
type ExitReviewSettlementBoundary struct {
	BoundaryOrder    int64  `json:"boundary_order"`
	SettlementID     string `json:"settlement_id"`
	Period           string `json:"period"`
	CurrencyCode     string `json:"currency_code"`
	Revision         int64  `json:"revision"`
	LedgerIndex      int64  `json:"ledger_index"`
	SettlementHash   string `json:"settlement_hash"`
	SourceFingerprint string `json:"source_fingerprint"`
	AllocationHash   string `json:"allocation_hash"`
}

type ExitReviewRecord struct {
	ReviewID                     string `json:"review_id"`
	RulesetVersion               string `json:"ruleset_version"`
	RecordDate                   string `json:"record_date"`
	TargetDeploymentID           string `json:"target_deployment_id"`
	ClaimActionID                string `json:"claim_action_id"`
	GroupID                      string `json:"group_id"`
	LegalName                    string `json:"legal_name"`
	CheckpointHash               string `json:"checkpoint_hash"`
	ThroughLedgerIndex           int64  `json:"through_ledger_index"`
	LedgerHeadHash               string `json:"ledger_head_hash"`
	MerkleTreeSize               int64  `json:"merkle_tree_size"`
	MerkleRootHash               string `json:"merkle_root_hash"`
	ThroughAuditIndex            int64  `json:"through_audit_index"`
	AuditHeadHash                string `json:"audit_head_hash"`
	ThroughReviewIndex           int64  `json:"through_review_index"`
	ClaimReviewHeadHash          string `json:"claim_review_head_hash"`
	ThroughEligibilityIndex      int64  `json:"through_eligibility_index"`
	EligibilityHeadHash          string `json:"eligibility_head_hash"`
	ThroughSettlementLedgerIndex int64  `json:"through_settlement_ledger_index"`
	SettlementBoundaryCount      int64  `json:"settlement_boundary_count"`
	SettlementBoundaryHash       string `json:"settlement_boundary_hash"`
	DeploymentCount              int64  `json:"deployment_count"`
	MembershipHash               string `json:"membership_hash"`
	FrozenAt                     string `json:"frozen_at"`
	RecordHash                   string `json:"record_hash"`
	RegistryScope                string `json:"registry_scope"`
	RegistryKeyID                string `json:"registry_key_id"`
	Deployments                  []ExitReviewDeployment `json:"deployments"`
	Settlements                  []ExitReviewSettlementBoundary `json:"settlements"`
}

type ExitReviewEvent struct {
	EventIndex        int64  `json:"event_index"`
	EventID           string `json:"event_id"`
	ReviewID          string `json:"review_id"`
	Action            string `json:"action"`
	ResultingStatus   string `json:"resulting_status"`
	EffectiveDate     string `json:"effective_date"`
	ActorRole         string `json:"actor_role"`
	ActorID           string `json:"actor_id"`
	Reference         string `json:"reference"`
	EvidenceHash      string `json:"evidence_hash"`
	ReasonCode        string `json:"reason_code,omitempty"`
	IdempotencyKey    string `json:"idempotency_key"`
	PayloadHash       string `json:"payload_hash"`
	RecordHash        string `json:"record_hash"`
	AcceptedAt        string `json:"accepted_at"`
	PreviousEventHash string `json:"previous_event_hash"`
	PreviousReviewEventHash string `json:"previous_review_event_hash"`
	EventHash         string `json:"event_hash"`
	RegistryScope     string `json:"registry_scope"`
	RegistryKeyID     string `json:"registry_key_id"`
	Signature         string `json:"signature"`
}

type ExitReview struct {
	Record            ExitReviewRecord `json:"record"`
	Status            string           `json:"status"`
	LatestEventIndex  int64            `json:"latest_event_index"`
	LatestEventHash   string           `json:"latest_event_hash"`
	LatestAction      string           `json:"latest_action"`
	LatestEffectiveDate string         `json:"latest_effective_date"`
	LatestActorRole   string           `json:"latest_actor_role"`
	LatestActorID     string           `json:"latest_actor_id"`
	LatestReference   string           `json:"latest_reference"`
	LatestEvidenceHash string          `json:"latest_evidence_hash"`
	LatestReasonCode  string           `json:"latest_reason_code,omitempty"`
	LatestAcceptedAt  string           `json:"latest_accepted_at"`
}

type ExitReviewMutationResult struct {
	Duplicate bool            `json:"duplicate"`
	Review    ExitReview      `json:"review"`
	Event     ExitReviewEvent `json:"event"`
}

type ExitReviewPage struct {
	Items          []ExitReview `json:"items"`
	NextEventIndex int64        `json:"next_event_index,omitempty"`
}

func ExitReviewMembershipHash(members []ExitReviewDeployment) string {
	lines := []string{
		"myscoutee-registry-exit-review-members-v1",
		strconv.Itoa(len(members)),
	}
	for _, member := range members {
		lines = append(
			lines,
			strconv.FormatInt(member.MemberOrder, 10),
			member.DeploymentID,
			member.ClaimActionID,
			strconv.FormatInt(member.ClaimAuditIndex, 10),
			member.ClaimAuditHash,
			strconv.FormatInt(member.ReviewIndex, 10),
			member.ReviewHash,
			strconv.FormatInt(member.EligibilityIndex, 10),
			member.EligibilityHash,
		)
	}
	return Digest(canonical(lines...))
}

func ExitReviewSettlementBoundaryHash(
	boundaries []ExitReviewSettlementBoundary,
) string {
	lines := []string{
		"myscoutee-registry-exit-review-settlements-v1",
		strconv.Itoa(len(boundaries)),
	}
	for _, boundary := range boundaries {
		lines = append(
			lines,
			strconv.FormatInt(boundary.BoundaryOrder, 10),
			boundary.SettlementID,
			boundary.Period,
			boundary.CurrencyCode,
			strconv.FormatInt(boundary.Revision, 10),
			strconv.FormatInt(boundary.LedgerIndex, 10),
			boundary.SettlementHash,
			boundary.SourceFingerprint,
			boundary.AllocationHash,
		)
	}
	return Digest(canonical(lines...))
}

func ExitReviewRecordHashMessage(record ExitReviewRecord) []byte {
	return canonical(
		"myscoutee-registry-exit-review-record-v1",
		record.ReviewID,
		record.RulesetVersion,
		record.RecordDate,
		record.TargetDeploymentID,
		record.ClaimActionID,
		record.GroupID,
		record.LegalName,
		record.CheckpointHash,
		strconv.FormatInt(record.ThroughLedgerIndex, 10),
		record.LedgerHeadHash,
		strconv.FormatInt(record.MerkleTreeSize, 10),
		record.MerkleRootHash,
		strconv.FormatInt(record.ThroughAuditIndex, 10),
		record.AuditHeadHash,
		strconv.FormatInt(record.ThroughReviewIndex, 10),
		record.ClaimReviewHeadHash,
		strconv.FormatInt(record.ThroughEligibilityIndex, 10),
		record.EligibilityHeadHash,
		strconv.FormatInt(record.ThroughSettlementLedgerIndex, 10),
		strconv.FormatInt(record.SettlementBoundaryCount, 10),
		record.SettlementBoundaryHash,
		strconv.FormatInt(record.DeploymentCount, 10),
		record.MembershipHash,
		record.FrozenAt,
		record.RegistryScope,
		record.RegistryKeyID,
	)
}

func ExitReviewEventPayloadMessage(event ExitReviewEvent) []byte {
	return canonical(
		"myscoutee-registry-exit-review-event-payload-v1",
		event.ReviewID,
		event.Action,
		event.ResultingStatus,
		event.EffectiveDate,
		event.ActorRole,
		event.ActorID,
		event.Reference,
		event.EvidenceHash,
		event.ReasonCode,
		event.RecordHash,
	)
}

func ExitReviewEventHashMessage(event ExitReviewEvent) []byte {
	return canonical(
		"myscoutee-registry-exit-review-event-v1",
		strconv.FormatInt(event.EventIndex, 10),
		event.EventID,
		event.ReviewID,
		event.Action,
		event.ResultingStatus,
		event.EffectiveDate,
		event.ActorRole,
		event.ActorID,
		event.Reference,
		event.EvidenceHash,
		event.ReasonCode,
		event.IdempotencyKey,
		event.PayloadHash,
		event.RecordHash,
		event.AcceptedAt,
		event.PreviousEventHash,
		event.PreviousReviewEventHash,
		event.RegistryScope,
		event.RegistryKeyID,
	)
}

func ExitReviewEventReceiptMessage(event ExitReviewEvent) []byte {
	return canonical(
		"myscoutee-registry-exit-review-event-receipt-v1",
		event.EventHash,
		event.RegistryKeyID,
	)
}
